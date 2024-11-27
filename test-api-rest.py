import requests
from urllib.parse import urljoin


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

    def test_methods(self, endpoint):
        """Prueba si los métodos HTTP están restringidos correctamente"""
        url = urljoin(self.base_url, endpoint)
        methods = ["GET", "POST", "PUT", "DELETE"]
        method_results = {}

        for method in methods:
            try:
                response = requests.request(method, url)
                method_results[method] = {
                    'status_code': response.status_code,
                    'response_text': response.text
                }
                
                print(f"Testing {method} on {url} | Status Code: {response.status_code}")
                
                # Categorización más detallada de las respuestas
                if response.status_code in [200, 201, 204]:
                    print(f"[+] Método {method} permitido correctamente")
                elif response.status_code == 400:
                    print(f"[!] Método {method} rechazado con código 400")
                elif response.status_code == 403:
                    print(f"[!] Método {method} no autorizado (403 Forbidden)")
                elif response.status_code == 405:
                    print(f"[!] Método {method} no permitido (405 Method Not Allowed)")
                else:
                    print(f"[?] Método {method} devolvió código inesperado: {response.status_code}")
            
            except Exception as e:
                method_results[method] = {
                    'error': str(e)
                }
                print(f"Error al probar método {method}: {e}")

        # Análisis adicional de los resultados
        self._analyze_method_restrictions(method_results)

    def _analyze_method_restrictions(self, method_results):
        """Analiza las restricciones de métodos HTTP"""
        print("\n--- Análisis de Restricciones de Métodos ---")
        
        # Verificar si hay un patrón consistente de restricciones
        status_codes = [result.get('status_code') for result in method_results.values() if 'status_code' in result]
        
        if len(set(status_codes)) == 1:
            print("[!] Todos los métodos devuelven el mismo código de estado")
        
        # Identificar métodos específicamente bloqueados
        blocked_methods = [
            method for method, result in method_results.items() 
            if result.get('status_code') in [400, 403, 405]
        ]
        
        if blocked_methods:
            print(f"[!] Métodos bloqueados: {', '.join(blocked_methods)}")
        
        # Verificar si hay métodos completamente permitidos
        allowed_methods = [
            method for method, result in method_results.items() 
            if result.get('status_code') in [200, 201, 204]
        ]
        
        if allowed_methods:
            print(f"[+] Métodos permitidos: {', '.join(allowed_methods)}")

        # Imprimir detalles completos para revisión
        print("\nDetalles completos:")
        for method, result in method_results.items():
            print(f"{method}: {result}")

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

    def test_register_validation(self, register_endpoint):
        """Prueba validaciones de registro"""
        invalid_user_data = [
            {"username": "", "password": "validpassword"},  # Nombre de usuario vacío
            {"username": "user", "password": ""},  # Contraseña vacía
            {"username": "user", "password": "short"},  # Contraseña demasiado corta
            {"username": "user", "password": "123456"},  # Contraseña débil
        ]
        for user_data in invalid_user_data:
            self.test_register(register_endpoint, user_data)

    def test_xss(self, endpoint):
        """Prueba de Cross-Site Scripting (XSS)"""
        payloads = [
            "<script>alert('XSS')</script>",
            "'; DROP TABLE users; --",
        ]
        for payload in payloads:
            url = urljoin(self.base_url, endpoint)
            response = requests.post(url, json={"input": payload})
            print(f"Testing XSS with payload: {payload} | Status Code: {response.status_code}")
            if payload in response.text:
                print(f"[!] Vulnerabilidad XSS detectada en {endpoint}")

    def test_csrf(self, endpoint):
        """Prueba de Cross-Site Request Forgery (CSRF)"""
        url = urljoin(self.base_url, endpoint)
        response = requests.post(url, data={"action": "delete_account"}, headers={"Referer": "http://malicious-site.com"})
        print(f"Testing CSRF at {url} | Status Code: {response.status_code}")
        if response.status_code == 200:
            print("[!] Posible vulnerabilidad CSRF detectada.")

    def test_command_injection(self, endpoint):
        """Prueba de inyección de comandos"""
        payload = {"input": "&& ls -la"}
        url = urljoin(self.base_url, endpoint)
        response = requests.post(url, json=payload)
        print(f"Testing command injection with payload: {payload} | Status Code: {response.status_code}")
        if "unexpected output" in response.text:  # Cambia esto según la respuesta esperada
            print("[!] Vulnerabilidad de inyección de comandos detectada.")

    def run_tests(self, endpoints):
        """Ejecuta todas las pruebas en los endpoints especificados"""
        for endpoint in endpoints:
            print(f"\n--- Probando endpoint: {endpoint} ---")
            try:
                self.test_sql_injection(endpoint)
                self.test_sensitive_endpoints()
                self.test_rate_limiting(endpoint)
                self.test_headers(endpoint)
                self.test_methods(endpoint)
                self.test_xss(endpoint)
                self.test_csrf(endpoint)
                self.test_command_injection(endpoint)
            except Exception as e:  # Captura cualquier excepción generada
                print(f"Error al probar {endpoint}: {e}")

# Ejemplo de uso
if __name__ == "__main__":
    tester = APISecurityTester("http://localhost:3000/")
    tester.run_tests(["/api/login", "/api/register", "/api/productos"])
    print("Pruebas completadas con éxito.")
    print("¡Felicitaciones! Tu API está segura.")
