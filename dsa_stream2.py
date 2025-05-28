import streamlit as st
import base64
import csv
import os
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

USUARIOS_CSV = 'usuarios.csv'

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def crear_usuario(usuario, contrasena):
    if not os.path.exists(USUARIOS_CSV):
        with open(USUARIOS_CSV, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['usuario', 'contrasena'])

    with open(USUARIOS_CSV, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['usuario'] == usuario:
                return False

    with open(USUARIOS_CSV, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([usuario, hash_password(contrasena)])
    return True

def verificar_usuario(usuario, contrasena):
    if not os.path.exists(USUARIOS_CSV):
        return False
    with open(USUARIOS_CSV, newline='') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row['usuario'] == usuario and row['contrasena'] == hash_password(contrasena):
                return True
    return False

def path_llaves(usuario):
    return f'llaves_rsa_{usuario}.csv'

def generar_llaves_y_guardar_csv(path_csv):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(path_csv, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['tipo', 'clave'])
        writer.writerow(['private_key', base64.b64encode(private_bytes).decode('utf-8')])
        writer.writerow(['public_key', base64.b64encode(public_bytes).decode('utf-8')])

    return private_key, public_key

def cargar_llaves_desde_csv(path_csv):
    with open(path_csv, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        claves = {row['tipo']: row['clave'] for row in reader}

    private_key = serialization.load_pem_private_key(
        base64.b64decode(claves['private_key']),
        password=None,
    )
    public_key = serialization.load_pem_public_key(
        base64.b64decode(claves['public_key'])
    )
    return private_key, public_key

def firmar_archivo(file_bytes, private_key):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_bytes)
    hashed_data = digest.finalize()

    signature = private_key.sign(
        hashed_data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        Prehashed(hashes.SHA256())
    )

    return signature

def verificar_firma(file_bytes, signature, public_key):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(file_bytes)
    hashed_data = digest.finalize()

    try:
        public_key.verify(
            signature,
            hashed_data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            Prehashed(hashes.SHA256())
        )
        return True
    except Exception:
        return False

# === STREAMLIT APP ===
st.title("🔐 Firma Digital con RSA")

menu = st.sidebar.selectbox("Menú", ["Registrarse", "Iniciar sesión"])

if menu == "Registrarse":
    st.header("Crear nuevo usuario")
    user = st.text_input("Nombre de usuario")
    pwd = st.text_input("Contraseña", type="password")
    if st.button("Registrar"):
        if crear_usuario(user, pwd):
            st.success("Usuario registrado correctamente.")
        else:
            st.error("El usuario ya existe.")

elif menu == "Iniciar sesión":
    st.header("Acceso de usuario")
    user = st.text_input("Usuario")
    pwd = st.text_input("Contraseña", type="password")
    if st.button("Iniciar sesión"):
        if verificar_usuario(user, pwd):
            st.session_state['usuario'] = user
            st.success(f"🟢 Bienvenido, {user}")
        else:
            st.error("❌ Usuario o contraseña incorrectos.")

    if 'usuario' in st.session_state:
        usuario = st.session_state['usuario']
        path_csv = path_llaves(usuario)
        if not os.path.exists(path_csv):
            _, _ = generar_llaves_y_guardar_csv(path_csv)

        private_key, public_key = cargar_llaves_desde_csv(path_csv)

        tab1, tab2 = st.tabs(["✍️ Firmar archivo", "🔎 Verificar firma"])

        with tab1:
            st.subheader("Firma de archivos")
            file_to_sign = st.file_uploader("Sube un archivo para firmar", type=None)
            if file_to_sign and st.button("Firmar"):
                file_bytes = file_to_sign.read()
                signature = firmar_archivo(file_bytes, private_key)
                st.success("✅ Archivo firmado correctamente.")
                st.download_button("Descargar firma", data=signature, file_name=file_to_sign.name + ".signature")

        with tab2:
            st.subheader("Verificación de firmas")
            file_original = st.file_uploader("Archivo original")
            file_signature = st.file_uploader("Archivo de firma (.signature)")

            # Selección de firmante
            if os.path.exists(USUARIOS_CSV):
                with open(USUARIOS_CSV, newline='') as f:
                    reader = csv.DictReader(f)
                    usuarios = [row['usuario'] for row in reader]

                firmante = st.selectbox("Selecciona el usuario que firmó el archivo", usuarios)
                if firmante:
                    path_firmante = path_llaves(firmante)
                    if os.path.exists(path_firmante):
                        _, public_key_firmante = cargar_llaves_desde_csv(path_firmante)

                        if file_original and file_signature and st.button("Verificar firma"):
                            result = verificar_firma(file_original.read(), file_signature.read(), public_key_firmante)
                            if result:
                                st.success("✅ Firma válida. El archivo es auténtico.")
                            else:
                                st.error("❌ Firma inválida o archivo modificado.")
                    else:
                        st.error("⚠️ No se encontró la llave del firmante.")
