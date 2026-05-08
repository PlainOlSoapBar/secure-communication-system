# About
Secure communication system written in Python. Uses a hybrid encryption scheme using RSA and AES keys to encrypt/decrypt messages. MAC is used to provide integrity and message authentication.
## Set-up
**1. Create virtual environment**
```
python -m venv venv
```
**2. Activate virtual environment**  

MacOS  
```
source venv/bin/activate
```
Windows
```
./venv/Scripts/activate
```
**3. Install dependencies**
```
pip install -r requirements.txt
```
## Running
**1. Edit `message.txt` with your desired message**  
**2. Generate RSA keys for the sender and receiver**  
```
python generate_keys.py
```
**3. Read and encrypt contents from `message.txt` to send to the receiver**  
```
python sender.py
```
**4. Recover plaintext from received data from the sender**  
```
python receiver.py
```