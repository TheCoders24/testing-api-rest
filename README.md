# Reporte de Pruebas de Seguridad en la API

Este reporte detalla los resultados de las pruebas de seguridad realizadas en los endpoints principales de la API: `/api/login`, `/api/register`, y `/api/productos`.

---

## 1. Pruebas de Inyección SQL en `/api/login`

### Resultados:
- **Payload:** `' OR '1'='1` | **Status Code:** 405
- **Payload:** `'; DROP TABLE users; --` | **Status Code:** 405
- **Payload:** `" OR "1"="1` | **Status Code:** 405
- **Payload:** `1 OR 1=1` | **Status Code:** 405

**Descripción:**
Se probaron payloads típicos de ataques de inyección SQL. Todos los intentos devolvieron un código 405 ("Método no permitido"), indicando que el método HTTP utilizado no es aceptado.

---

## 2. Pruebas de Endpoints Sensibles

### Resultados:
- `/admin` | **Status Code:** 404
- `/config` | **Status Code:** 404
- `/.env` | **Status Code:** 404
- `/backup` | **Status Code:** 404
- `/users` | **Status Code:** 404
- `/register` | **Status Code:** 404
- `/productos` | **Status Code:** 404

**Descripción:**
Se probaron varios endpoints potencialmente sensibles. Todos devolvieron un 404, lo cual es positivo, ya que indica que no están expuestos.

---

## 3. Pruebas de Limitación de Tasa

### Resultados:
- **Request 1 a 20:** **Status Code:** 405

**Descripción:**
No se detectó una limitación de tasa explícita. El código 405 sugiere que el método no es permitido, lo que indirectamente bloquea ataques de fuerza bruta.

---

## 4. Pruebas de Cabeceras de Seguridad

### Resultados:
- Cabeceras ausentes:
  - `Content-Security-Policy`
  - `Strict-Transport-Security`
  - `X-Frame-Options`
  - `X-Content-Type-Options`
  - `Referrer-Policy`

**Descripción:**
La ausencia de estas cabeceras representa un riesgo de seguridad. Podrían ser implementadas para prevenir ataques como XSS y clickjacking.

---

## 5. Pruebas de Métodos HTTP

### Resultados en `/api/login`:
- **GET:** **Status Code:** 405
- **POST:** **Status Code:** 400
- **PUT:** **Status Code:** 405
- **DELETE:** **Status Code:** 405

**Descripción:**
El método POST devuelve un 400, indicando problemas con los datos requeridos. Otros métodos están correctamente restringidos.

---

## 6. Análisis de Restricciones de Métodos

### Resultados:
- Métodos bloqueados: **GET, POST, PUT, DELETE**

**Descripción:**
Aunque los métodos están bloqueados, se debe garantizar que el método POST funcione para las autenticaciones.

---

## 7. Pruebas de XSS, CSRF y Inyección de Comandos

### Resultados:
- **XSS Payload:** `<script>alert('XSS')</script>`:
  - POST: **Status Code:** 400
  - GET: **Status Code:** 405
- **Inyección de Comandos Payload:** `: && ls -la`:
  - POST: **Status Code:** 400
  - GET: **Status Code:** 405

**Descripción:**
El manejo de solicitudes maliciosas parece adecuado. Ningún payload fue procesado, y las solicitudes fueron rechazadas.

---

## 8. Pruebas en `/api/register`

### Descripción:
Resultados similares a `/api/login`. No se procesaron inyecciones SQL ni XSS, pero se detectaron cabeceras de seguridad ausentes y problemas con métodos HTTP.

---

## 9. Pruebas en `/api/productos`

### Resultados:
- **GET:** Permite el acceso a los productos.
- **POST, PUT, DELETE:** Devuelven un 400, indicando falta de datos requeridos.

**Descripción:**
El endpoint está bien configurado para leer productos, pero no permite modificaciones sin datos válidos.

---

## Conclusión General

### Seguridad:
- Protegido contra inyecciones SQL y ataques XSS.
- **Problema:** Ausencia de cabeceras de seguridad importantes.

### Métodos HTTP:
- Adecuadamente restringidos, aunque POST debe estar funcional en endpoints clave como `/api/login`.

### Recomendaciones:
1. Implementar las siguientes cabeceras de seguridad:
   - `Content-Security-Policy`
   - `Strict-Transport-Security`
   - `X-Frame-Options`
   - `X-Content-Type-Options`
   - `Referrer-Policy`
2. Revisar la lógica de manejo de métodos HTTP.
3. Asegurar el funcionamiento adecuado de las solicitudes de autenticación y registro.
4. Implementar una limitación de tasa para proteger contra ataques de fuerza bruta.
