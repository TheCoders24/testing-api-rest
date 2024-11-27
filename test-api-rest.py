import requests
from urllib.parse import urljoin
import random


class APISecurityTester:
    def __init__(self, base_url):
        self.base_url = base_url

    def test_sql_injection(self, endpoint):
        """Prueba inyección SQL"""
        payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "\" OR \"1\"=\"1",
            "1 OR 1=1",
        ]
        for payload in payloads:
            url = urljoin(self.base_url, endpoint)
            response = requests.get(url, params={"input": payload})
            print(f"Payload: {payload} | Status Code: {response.status_code}")
            if "error" in response.text.lower() or "syntax" in response.text.lower():
                print(f"[!] Posible vulnerabilidad de inyección SQL detectada en {endpoint}")

    def test_sensitive_endpoints(self):
        """Prueba endpoints sensibles o expuestos"""
        endpoints = [
            "/admin",
            "/config",
            "/.env",
            "/backup",
            "/users",
            "/register",
            "/productos"
        ]
        for endpoint in endpoints:
            url = urljoin(self.base_url, endpoint)
            response = requests.get(url)
            print(f"Testing {url} | Status Code: {response.status_code}")
            if response.status_code == 200:
                print(f"[!] Endpoint sensible detectado: {url}")

    def test_rate_limiting(self, endpoint):
        """Prueba limitación de tasa"""
        url = urljoin(self.base_url, endpoint)
        for _ in range(20):  # Simula múltiples solicitudes rápidas
            response = requests.get(url)
            print(f"Status Code: {response.status_code}")
            if response.status_code == 429:  # Código HTTP para límite alcanzado
                print("[+] Limitación de tasa activa en el endpoint")
                break
        else:
            print("[!] Endpoint sin limitación de tasa aparente")

    def test_headers(self, endpoint):
        """Verifica encabezados de seguridad"""
        url = urljoin(self.base_url, endpoint)
        response = requests.get(url)
        security_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy"
        ]
        print(f"Testing headers for {url}")
        for header in security_headers:
            if header not in response.headers:
                print(f"[!] Header de seguridad ausente: {header}")
            else:
                print(f"[+] Header presente: {header}")

    def test_login(self, login_endpoint, credentials):
        """Prueba login con diferentes credenciales"""
        url = urljoin(self.base_url, login_endpoint)
        response = requests.post(url, json=credentials)
        print(f"Testing login at {url} | Status Code: {response.status_code}")
        if response.status_code == 200 and "token" in response.json():
            print("[+] Login exitoso, token recibido.")
        elif response.status_code == 401:
            print("[!] Credenciales inválidas detectadas correctamente.")
        else:
            print(f"[!] Respuesta inesperada: {response.json()}")

    def test_register(self, register_endpoint, user_data):
        """Prueba registro de usuarios"""
        url = urljoin(self.base_url, register_endpoint)
        response = requests.post(url, json=user_data)
        print(f"Testing registration at {url} | Status Code: {response.status_code}")
        if response.status_code == 201:
            print("[+] Registro exitoso.")
        elif response.status_code == 400:
            print("[!] Error en datos de registro.")
        else:
            print(f"[!] Respuesta inesperada: {response.json()}")

    def test_methods(self, endpoint):
        """Prueba si los métodos HTTP están restringidos correctamente"""
        url = urljoin(self.base_url, endpoint)
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
        for method in methods:
            response = requests.request(method, url)
            print(f"Testing {method} at {url} | Status Code: {response.status_code}")
            if method not in ["GET", "POST"] and response.status_code == 200:
                print(f"[!] Método no autorizado permitido: {method}")

    def run_tests(self):
        print("Iniciando pruebas de seguridad de la API...")
        self.test_sql_injection("/api/register")
        self.test_sensitive_endpoints()
        self.test_rate_limiting("/api/productos")
        self.test_headers("/")
        # Testear login y registro
        #self.test_login("/api/login", {"username": "admin", "password": "password123"})
        #self.test_register("/api/register", {"username": "newuser", "password": "securepassword"})
        
        login_credentials = [
        {"username": "admin", "password": "password123"},
        {"username": "user1", "password": "mypassword"},
        {"username": "testuser", "password": "testpass"},
        {"username": "guest", "password": "guestpass"},
        {"username": "randomuser", "password": "randompass123"},
        ]

        register_data = [
        {"username": "newuser", "password": "securepassword"},
        {"username": "anotheruser", "password": "anotherpass"},
        {"username": "user2", "password": "user2password"},
        {"username": "testuser2", "password": "testpass2"},
        {"username": "randomuser2", "password": "randompass456"},
        ]

        random_login = random.choice(login_credentials)
        random_register = random.choice(register_data)

        # Ejecución de las pruebas
        self.test_login("/api/login", random_login)
        self.test_register("/api/register", random_register)
        self.test_methods("/api/productos")


if __name__ == "__main__":
    # Cambia 'http://localhost:3000' por la URL base de tu API
    tester = APISecurityTester(base_url="http://localhost:3000")
    tester.run_tests()
