from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
app.secret_key = 'secretkey'

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Database setup

def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()


    c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                password TEXT NOT NULL,
                rsa_public_key TEXT NOT NULL,
                dsa_public_key TEXT NOT NULL,
                rsa_private_key_path TEXT NOT NULL,  
                dsa_private_key_path TEXT NOT NULL) 
              ''')

    c.execute('''CREATE TABLE IF NOT EXISTS documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT NOT NULL,
        signature TEXT NOT NULL,
        r TEXT NOT NULL,
        s TEXT NOT NULL,
        public_key TEXT NOT NULL,
        metadata TEXT NOT NULL,
        upload_date TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id))''')

    c.execute('''CREATE TABLE IF NOT EXISTS shared_documents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        doc_id INTEGER,
        recipient_id INTEGER,
        encrypted_filename TEXT NOT NULL,
        FOREIGN KEY (doc_id) REFERENCES documents(id),
        FOREIGN KEY (recipient_id) REFERENCES users(id))''')

    conn.commit()
    conn.close()


def generate_rsa_keys(username):
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Export the private key securely to a file
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()  # or with encryption
    )

    # Save the private key to a file
    private_key_path = f"private_keys/{username}_rsa_private.pem"
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)
    with open(private_key_path, 'wb') as private_file:
        private_file.write(private_pem)

    # Export the public key for storage in the database
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_path, public_pem.decode()

# Function to generate DSA keys
def generate_dsa_keys(username):
    private_key = dsa.generate_private_key(key_size=2048)
    public_key = private_key.public_key()

    # Export private key to a file
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    private_key_path = f"private_keys/{username}_dsa_private.pem"
    os.makedirs(os.path.dirname(private_key_path), exist_ok=True)
    with open(private_key_path, 'wb') as private_file:
        private_file.write(private_pem)

    # Export the public key for storage in the database
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_path, public_pem.decode()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])

        # Generate RSA and DSA keys
        rsa_private_key_path, rsa_public = generate_rsa_keys(username)
        dsa_private_key_path, dsa_public = generate_dsa_keys(username)

        # Store RSA and DSA keys in the database
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('''INSERT INTO users (username, email, password, rsa_public_key, dsa_public_key, 
                   rsa_private_key_path, dsa_private_key_path) VALUES (?, ?, ?, ?, ?, ?, ?)''', 
                  (username, email, password, rsa_public, dsa_public, rsa_private_key_path, dsa_private_key_path))  
        conn.commit()
        conn.close()
        return redirect('/login')

    return render_template('register.html')



# Routes

@app.route('/')
def home():
    return redirect('/login')



@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user_id'] = user[0]
            return redirect('/dashboard')
        else:
            error = 'Invalid credentials'

    return render_template('login.html', error=error)



@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/login')
    return render_template('dashboard.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        document = request.files['document']
        
        # Check if file is valid (e.g., not empty)
        if document and allowed_file(document.filename):  # Implement allowed_file function
            filename = document.filename
            filepath = os.path.join(UPLOAD_FOLDER, filename)

            # Save the uploaded document to the 'uploads' folder
            document.save(filepath)

            # Read the saved file content for signing
            with open(filepath, 'rb') as f:
                original_data = f.read()

            # Retrieve user from the session and get their DSA private and public key from the database
            user_id = session['user_id']
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute('SELECT dsa_private_key_path, dsa_public_key FROM users WHERE id = ?', (user_id,))
            result = c.fetchone()
            if not result:
                return "Error: Private Key not found."

            dsa_private_key_path = result[0]
            dsa_public_key_pem = result[1]
            conn.close()

            # Ensure private key file exists before proceeding
            if not os.path.exists(dsa_private_key_path):
                return "Error: DSA Private Key file is missing."

            # Load the DSA private key from the file
            with open(dsa_private_key_path, 'rb') as private_file:
                private_pem = private_file.read()

            # Deserialize the private key
            try:
                private_key = serialization.load_pem_private_key(private_pem, password=None)
            except ValueError as e:
                return f"Error: Could not load DSA private key. {str(e)}"

            # Sign the document with the DSA private key
            try:
                signature = private_key.sign(original_data, hashes.SHA256())
                r, s = decode_dss_signature(signature)
            except Exception as e:
                return f"Error: Could not sign the document. {str(e)}"

            # Get the current timestamp
            upload_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            metadata = f"DSA signed document | User ID: {session['user_id']}"

            # Store document metadata in the database
            conn = sqlite3.connect('database.db')
            c = conn.cursor()
            c.execute('''INSERT INTO documents (user_id, filename, signature, r, s, public_key, metadata, upload_date)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                      (session['user_id'], filename, signature.hex(), str(r), str(s),
                       dsa_public_key_pem, metadata, upload_date))
            conn.commit()
            conn.close()

            return render_template('upload.html',
                                   message="Document signed successfully!",
                                   r=r, s=s,
                                   public_key=dsa_public_key_pem,
                                   filename=filename,
                                   timestamp=upload_date)

    return render_template('upload.html')

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'pdf', 'docx', 'txt'}  # Add more extensions as needed
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS



@app.route('/documents')
def documents():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''SELECT id, filename, upload_date, r, s, public_key, metadata FROM documents WHERE user_id=?''', (session['user_id'],))
    documents = c.fetchall()

    # Fetch usernames of other users for sharing
    c.execute('SELECT username FROM users WHERE id != ?', (session['user_id'],))
    users = [u[0] for u in c.fetchall()]

    conn.close()

    # Format the upload_date if it exists
    formatted_documents = []
    for doc in documents:
        raw_date = doc[2]
        if raw_date:
            try:
                upload_date = datetime.strptime(raw_date, '%Y-%m-%d %H:%M:%S')
                formatted_date = upload_date.strftime('%B %d, %Y %I:%M %p')
            except ValueError:
                formatted_date = raw_date  # fallback if format is off
        else:
            formatted_date = "N/A"
        
        formatted_documents.append((doc[0], doc[1], formatted_date) + doc[3:])

    return render_template('documents.html', documents=formatted_documents, users=users)



# @app.route('/verify', methods=['GET', 'POST'])
# def verify():
#     message = None
#     if request.method == 'POST':
#         document = request.files['document']
#         r = int(request.form['r'])
#         s = int(request.form['s'])
#         public_key_pem = request.form['public_key']

#         try:
#             # Load the public key
#             public_key = serialization.load_pem_public_key(public_key_pem.encode())

#             # Recreate the DSA signature from r and s values
#             signature = encode_dss_signature(r, s)

#             # Read document data
#             document_data = document.read()

#             # Verify the signature using the public key
#             public_key.verify(signature, document_data, hashes.SHA256())
#             message = "Signature is valid."
#         except InvalidSignature:
#             message = "Invalid signature."
#         except Exception as e:
#             message = f"Error: {str(e)}"

#     return render_template('verify.html', message=message)

from flask import jsonify

from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature

@app.route('/verify/<filename>')
def verify(filename):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''
        SELECT r, s, public_key 
        FROM documents 
        WHERE filename=? AND user_id=?
    ''', (filename, session['user_id']))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"error": "File not found"}), 404

    try:
        r = int(row[0])
        s = int(row[1])
        public_key_pem = row[2]
    except (ValueError, TypeError):
        return jsonify({"error": "Invalid signature values in database."}), 400

    filepath = os.path.join("uploads", filename)

    try:
        with open(filepath, "rb") as f:
            document_data = f.read()
    except FileNotFoundError:
        return jsonify({"error": "Document file not found"}), 404

    try:
        public_key = load_pem_public_key(public_key_pem.encode())
        signature = encode_dss_signature(r, s)

        public_key.verify(
            signature,
            document_data,
            hashes.SHA256()
        )

        return jsonify({"message": "Signature is VALID ✅"})
    except InvalidSignature:
        return jsonify({"message": "Signature is INVALID ❌"})
    except Exception as e:
        return jsonify({"message": f"Error: {str(e)}"})


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect('/login')

@app.route('/shared')
def view_shared_documents():
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Join shared_documents with documents and users to get full info
    c.execute('''
        SELECT sd.id, d.filename, d.upload_date, u.username, sd.encrypted_filename
        FROM shared_documents sd
        JOIN documents d ON sd.doc_id = d.id
        JOIN users u ON d.user_id = u.id
        WHERE sd.recipient_id = ?
        ORDER BY sd.id DESC
    ''', (session['user_id'],))
    
    rows = c.fetchall()
    conn.close()

    shared_docs = []
    for row in rows:
        shared_docs.append({
            'id': row[0],
            'original_filename': row[1],
            'shared_date': row[2],
            'sender_username': row[3],
            'encrypted_filename': row[4],
        })

    return render_template('shared.html', shared_docs=shared_docs)

from cryptography.hazmat.primitives.asymmetric import utils

@app.route('/share_document/<doc_id>', methods=['GET', 'POST'])
def share_document(doc_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Fetch document details using doc_id
    c.execute('SELECT * FROM documents WHERE id=? AND user_id=?', (doc_id, session['user_id']))
    doc = c.fetchone()
    if not doc:
        conn.close()
        return "Document not found or access denied."

    if request.method == 'POST':
        recipient_username = request.form['recipient']

        # ✅ FIX: Fetch RSA public key correctly
        c.execute('SELECT id, rsa_public_key FROM users WHERE username=?', (recipient_username,))
        recipient = c.fetchone()
        if not recipient:
            conn.close()
            return jsonify({"message": "Recipient not found."})

        recipient_id = recipient[0]
        recipient_rsa_public_key_pem = recipient[1]

        try:
            recipient_rsa_public_key = serialization.load_pem_public_key(recipient_rsa_public_key_pem.encode())
        except Exception as e:
            conn.close()
            return f"Failed to load RSA public key: {str(e)}"

        # Load original file
        filename = doc[2]
        filepath = os.path.join("uploads", filename)
        if not os.path.exists(filepath):
            conn.close()
            return "Original file not found on disk."

        with open(filepath, "rb") as f:
            file_data = f.read()

        # Encrypt the document using recipient's RSA public key
        try:
            encrypted_data = recipient_rsa_public_key.encrypt(
                file_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except Exception as e:
            conn.close()
            return jsonify({"message": "Encryption failed: " + str(e)})

        # Save encrypted file
        encrypted_filename = f"enc_{doc_id}_to_{recipient_username}_{datetime.now().strftime('%Y%m%d%H%M%S')}.bin"
        encrypted_filepath = os.path.join("shared_docs", encrypted_filename)
        os.makedirs("shared_docs", exist_ok=True)

        with open(encrypted_filepath, 'wb') as f:
            f.write(encrypted_data)

        # Store the sharing record
        c.execute('''INSERT INTO shared_documents (doc_id, recipient_id, encrypted_filename)
                     VALUES (?, ?, ?)''',
                  (doc_id, recipient_id, encrypted_filename))
        conn.commit()
        conn.close()

        return jsonify({"message": "Document shared successfully!"})

    # GET method: show dropdown of other users
    c.execute("SELECT username FROM users WHERE id != ?", (session['user_id'],))
    users = [u[0] for u in c.fetchall()]
    conn.close()

    return render_template('documents.html', doc=doc, users=users)


from flask import send_from_directory

@app.route('/download_encrypted/<filename>')
def download_encrypted(filename):
    return send_from_directory('shared_docs', filename, as_attachment=True)

from flask import make_response, jsonify
@app.route('/decrypt_document/<int:shared_doc_id>')
def decrypt_document(shared_doc_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    try:
        # Get the shared document record
        c.execute('''
            SELECT sd.encrypted_filename, u.rsa_private_key_path 
            FROM shared_documents sd
            JOIN users u ON sd.recipient_id = u.id
            WHERE sd.id=? AND sd.recipient_id=?
        ''', (shared_doc_id, session['user_id']))
        shared_doc = c.fetchone()
        
        if not shared_doc:
            return jsonify({"error": "Document not found or access denied"}), 404

        encrypted_filename = shared_doc[0]
        private_key_path = shared_doc[1]

        # Load the encrypted file
        encrypted_filepath = os.path.join("shared_docs", encrypted_filename)
        if not os.path.exists(encrypted_filepath):
            return jsonify({"error": "Encrypted file not found"}), 404

        with open(encrypted_filepath, 'rb') as f:
            encrypted_data = f.read()

        # Load the private key
        if not os.path.exists(private_key_path):
            return jsonify({"error": "Private key not found"}), 404

        with open(private_key_path, 'rb') as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None
            )

        # Decrypt the data
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Create a response with the decrypted data
        original_filename = encrypted_filename.split('_')[3]  # Extract original filename
        response = make_response(decrypted_data)
        response.headers['Content-Disposition'] = f'attachment; filename=decrypted_{original_filename}'
        response.headers['Content-Type'] = 'application/octet-stream'

        return response

    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 500
    finally:
        conn.close()

@app.route('/verify_shared/<int:shared_doc_id>')
def verify_shared_document(shared_doc_id):
    if 'user_id' not in session:
        return redirect('/login')

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    try:
        # Get the document and signature details
        c.execute('''
            SELECT d.filename, d.r, d.s, d.public_key
            FROM shared_documents sd
            JOIN documents d ON sd.doc_id = d.id
            WHERE sd.id=? AND sd.recipient_id=?
        ''', (shared_doc_id, session['user_id']))
        doc = c.fetchone()
        
        if not doc:
            return jsonify({"error": "Document not found or access denied"}), 404

        filename = doc[0]
        r = int(doc[1])
        s = int(doc[2])
        public_key_pem = doc[3]

        # Load the document
        filepath = os.path.join("uploads", filename)
        if not os.path.exists(filepath):
            return jsonify({"error": "Original document not found"}), 404

        with open(filepath, 'rb') as f:
            document_data = f.read()

        # Load the public key
        public_key = serialization.load_pem_public_key(public_key_pem.encode())

        # Recreate the signature
        signature = encode_dss_signature(r, s)

        # Verify the signature
        try:
            public_key.verify(
                signature,
                document_data,
                hashes.SHA256()
            )
            return jsonify({"message": "Signature is VALID ✅", "status": "success"})
        except InvalidSignature:
            return jsonify({"message": "Signature is INVALID ❌", "status": "error"})
        except Exception as e:
            return jsonify({"message": f"Verification error: {str(e)}", "status": "error"})

    except Exception as e:
        return jsonify({"error": f"Verification failed: {str(e)}", "status": "error"}), 500
    finally:
        conn.close()


if __name__ == '__main__':
    init_db()
    app.run(debug=True)
