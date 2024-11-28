import requests
from urllib.parse import urljoin


class APISecurityTester:
    def __init__(self, base_url):
        self.base_url = base_url
        self.security_headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer"
        }

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
                # Añadir cabeceras de seguridad a la solicitud
                headers = {
                    **self.security_headers,
                    "User-Agent": "APISecurityTester/1.0"
                }
                
                response = requests.request(method, url, headers=headers)
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
            response = requests.get(url, headers=self.security_headers)
            print(f"Testing {url} | Status Code: {response.status_code}")
            if response.status_code == 200:
                print(f"[!] Endpoint sensible detectado: {url}")

    def test_rate_limiting(self, endpoint):
        """Prueba limitación de tasa"""
        url = urljoin(self.base_url, endpoint)
        for i in range(20):  # Simula múltiples solicitudes rápidas
            try:
                response = requests.get(url, headers={
                    **self.security_headers,
                    "X-Forwarded-For": f"http://localhost:3000{i}"  # Simular diferentes IPs
                })
                print(f"Request {i+1} - Status Code: {response.status_code}")
                if response.status_code == 429:  # Código HTTP para límite alcanzado
                    print("[+] Limitación de tasa activa en el endpoint")
                    break
            except Exception as e:
                print(f"Error en solicitud {i+1}: {e}")
        else:
            print("[!] Endpoint sin limitación de tasa aparente")

    def test_headers(self, endpoint):
        """Verifica encabezados de seguridad"""
        url = urljoin(self.base_url, endpoint)
        response = requests.get(url, headers=self.security_headers)
        
        print(f"Testing headers for {url}")
        
        # Verificar cabeceras de seguridad definidas
        for header, expected_value in self.security_headers.items():
            if header not in response.headers:
                print(f"[!] Header de seguridad ausente: {header}")
            else:
                current_value = response.headers[header]
                print(f"[+] Header presente: {header}")
                # Opcional: Verificar si el valor es el esperado
                if current_value != expected_value:
                    print(f"   [?] Valor actual: {current_value}")
                    print(f"   [?] Valor esperado: {expected_value}")

    # Resto de los métodos permanecen igual...

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

                # Nuevos métodos de prueba
                self.test_xss(endpoint)
                self.test_csrf(endpoint)
                self.test_command_injection(endpoint)

            except Exception as e:
                 print(f"Error al probar {endpoint}: {e}")
    def test_xss(self, endpoint):
        """Prueba de Cross-Site Scripting (XSS)"""
        url = urljoin(self.base_url, endpoint)
        
        payloads = [
            "<script>alert('XSS')</script>",
            "'; DROP TABLE users; --",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for payload in payloads:
            try:
                # Intentar con diferentes métodos y tipos de solicitud
                # Prueba POST con payload en JSON
                response_json = requests.post(url, 
                    json={"input": payload}, 
                    headers=self.security_headers
                )
                
                # Prueba GET con payload en parámetros
                response_get = requests.get(url, 
                    params={"input": payload}, 
                    headers=self.security_headers
                )
                
                print(f"Testing XSS with payload: {payload}")
                print(f"POST Status Code: {response_json.status_code}")
                print(f"GET Status Code: {response_get.status_code}")
                
                # Verificar si el payload se refleja en la respuesta
                if payload in response_json.text or payload in response_get.text:
                    print(f"[!] Posible vulnerabilidad XSS detectada en {endpoint}")
                    print("Respuesta JSON:", response_json.text)
                    print("Respuesta GET:", response_get.text)
                
            except Exception as e:
                print(f"Error al probar XSS con payload {payload}: {e}")

    def test_csrf(self, endpoint):
        """Prueba de Cross-Site Request Forgery (CSRF)"""
        url = urljoin(self.base_url, endpoint)
        # Crear solicitudes con diferentes orígenes y referentes
        csrf_test_cases = [
            {
                "headers": {
                    "Origin": "http://localhost:3000",
                    "Referer": "http://localhost:3000/"
                },
                "data": {"action": "delete_account"}
            },
            {
                "headers": {
                    "Origin": "http://localhost:3000",
                    "Referer": "http://localhost:3000"
                },
                "data": {"action": "123456789"}
            }
        ]
        
        for test_case in csrf_test_cases:
            try:
                response = requests.post(
                    url, 
                    json=test_case["data"], 
                    headers={
                        **self.security_headers,
                        **test_case["headers"]
                    }
                )
                
                print(f"Testing CSRF at {url}")
                print(f"Headers: {test_case['headers']}")
                print(f"Status Code: {response.status_code}")
                
                # Verificar si la solicitud se procesa sin validación adecuada
                if response.status_code in [200, 201]:
                    print("[!] Posible vulnerabilidad CSRF detectada")
                    print("Respuesta:", response.text)
                
            except Exception as e:
                print(f"Error al probar CSRF: {e}")

    def test_command_injection(self, endpoint):
        """Prueba de inyección de comandos"""
        url = urljoin(self.base_url, endpoint)
        
        payload_cases = [
            "&& ls -la",
            "$(whoami)",
            "`ls -la`",
            "| cat /etc/passwd",
            ";cat /etc/passwd"
        ]
        
        for payload in payload_cases:
            try:
                # Probar diferentes métodos de inyección
                response_json = requests.post(
                    url, 
                    json={"input": payload}, 
                    headers=self.security_headers
                )
                
                response_get = requests.get(
                    url, 
                    params={"input": payload}, 
                    headers=self.security_headers
                )
                
                print(f"Testing command injection with payload: {payload}")
                print(f"POST Status Code: {response_json.status_code}")
                print(f"GET Status Code: {response_get.status_code}")
                
                # Verificar si hay indicios de ejecución de comandos
                if any([
                    "total" in response_json.text,  # Salida de ls -la
                    "root" in response_json.text,   # Usuario root
                    "passwd" in response_json.text  # Contenido de archivo sensible
                ]):
                    print("[!] Posible vulnerabilidad de inyección de comandos")
                    print("Respuesta POST:", response_json.text)
                    print("Respuesta GET:", response_get.text)
                
            except Exception as e:
                print(f"Error al probar inyección de comandos con payload {payload}: {e}")
# Ejemplo de uso
if __name__ == "__main__":
    tester = APISecurityTester("http://localhost:3000/")
    tester.run_tests(["/api/login", "/api/register", "/api/productos"])
    print("Pruebas completadas con éxito.")
    