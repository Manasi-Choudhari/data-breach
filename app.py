from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import joblib
from web3 import Web3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Initialize the Flask app and SQLAlchemy
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
db = SQLAlchemy(app)

# Define the User and AccessLog Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class AccessLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_accessed = db.Column(db.String(120), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False)

# Ensure the database is created
with app.app_context():
    db.create_all()

# Load the AI model
model = joblib.load("anomaly_detector.pkl")

# Function to send email alerts
def send_email_alert(to_email, subject, body):
    sender_email = "your_email@example.com"
    sender_password = "your_email_password"

    # Set up the email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    # Send the email
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(msg)

# Register User Route
@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.json
        if not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Username and password are required'}), 400

        user = User(username=data['username'], password=data['password'])
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully!'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Log Access Route
@app.route('/log', methods=['POST'])
def log_access():
    try:
        data = request.json

        # Validate input
        if not data.get('user_id') or not data.get('file_accessed'):
            return jsonify({'error': 'user_id and file_accessed are required'}), 400

        # Extract features
        user_id = data['user_id']
        file_accessed = data['file_accessed']
        timestamp = datetime.now()
        hour = timestamp.hour  # Extract hour from the current time

        # Detect anomaly
        features = [[user_id, hour]]
        prediction = model.predict(features)

        # Log the access
        access_log = AccessLog(user_id=user_id, file_accessed=file_accessed, timestamp=timestamp)
        db.session.add(access_log)
        db.session.commit()

        # Respond based on prediction
        if prediction[0] == -1:
            send_email_alert("admin@example.com", "Anomaly Detected", "An unusual access pattern was detected.")
            return jsonify({'alert': 'Anomaly detected!'}), 400

        return jsonify({'message': 'Access logged successfully!'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Connect to the Ethereum blockchain using Web3
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
contract_address = '0x710a4dC1FabEbf07f41Ab860ef316b49Abe1731B'
abi = [
    {
        "inputs": [
            {"internalType": "uint256", "name": "id", "type": "uint256"},
            {"internalType": "string", "name": "fileAccessed", "type": "string"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "string", "name": "userId", "type": "string"}
        ],
        "name": "addLog",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    },
    {
        "inputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
        "name": "logs",
        "outputs": [
            {"internalType": "uint256", "name": "id", "type": "uint256"},
            {"internalType": "string", "name": "fileAccessed", "type": "string"},
            {"internalType": "uint256", "name": "timestamp", "type": "uint256"},
            {"internalType": "string", "name": "userId", "type": "string"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]
contract = w3.eth.contract(address=contract_address, abi=abi)

# Function to log to the Ethereum blockchain
def log_to_blockchain(user_id, file_accessed, timestamp):
    tx = contract.functions.addLog(user_id, file_accessed, timestamp).transact()
    return w3.eth.wait_for_transaction_receipt(tx)

# Analytics Route
@app.route('/analytics', methods=['GET'])
def analytics():
    # Query AccessLog for normal and anomaly counts
    normal_count = AccessLog.query.filter_by(status="Normal").count()
    anomaly_count = AccessLog.query.filter_by(status="Anomaly").count()

    return jsonify({"normal": normal_count, "anomalies": anomaly_count})

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True)
