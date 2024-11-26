import requests
from urllib.parse import urljoin

class APISecurityTester:
    def __init__(self, base_url):
        self.base_url = base_url

    def test_sql_injection(self, endpoint):
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
        endpoints = [
            "/admin",
            "/config",
            "/.env",
            "/backup",
            "/users"
        ]
        for endpoint in endpoints:
            url = urljoin(self.base_url, endpoint)
            response = requests.get(url)
            print(f"Testing {url} | Status Code: {response.status_code}")
            if response.status_code == 200:
                print(f"[!] Endpoint sensible detectado: {url}")

    def test_rate_limiting(self, endpoint):
        url = urljoin(self.base_url, endpoint)
        for _ in range(20):  # Simula múltiples solicitudes rápidas
            response = requests.get(url)
            print(f"Status Code: {response.status_code}")
            if response.status_code == 429:  # Código HTTP para límite alcanzado
                print("[+] Limitación de tasa activa en el endpoint")
                break
        else:
            print("[!] Endpoint sin limitación de tasa aparente")

    def run_tests(self):
        print("Iniciando pruebas de seguridad de la API...")
        self.test_sql_injection("/api/register")
        self.test_sensitive_endpoints()
        self.test_rate_limiting("/api/productos")


if __name__ == "__main__":
    # Cambia 'http://localhost:3000' por la URL base de tu API
    tester = APISecurityTester(base_url="http://localhost:3000")
    tester.run_tests()
