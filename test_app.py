import unittest
from unittest.mock import patch
from app import app, scan_port, check_vulnerabilities

class TestPortScanner(unittest.TestCase):

    # Тест для функції перевірки вразливостей
    def test_check_vulnerabilities(self):
        open_ports = [80, 443]
        result = check_vulnerabilities(open_ports)
        
        self.assertIn(80, result, "Port 80 should have vulnerabilities")
        self.assertIn(443, result, "Port 443 should have vulnerabilities")
        self.assertEqual(result[80][0], 'HTTP', "Port 80 should be HTTP service")
        self.assertGreater(len(result[80][1]), 0, "Port 80 should have vulnerabilities")

    # Тест для перевірки порту (використовуємо мокінг)
    @patch('app.socket.socket')
    def test_scan_port_open(self, mock_socket):
        # Мок інтерфейсу socket для того, щоб завжди повертати відкритий порт
        mock_socket.return_value.connect_ex.return_value = 0  # 0 означає, що порт відкритий
        
        ip = '127.0.0.1'
        port = 80
        result = scan_port(ip, port)
        
        self.assertEqual(result[1], True, f"Port {port} should be open")

    # Тест для маршруту Flask (інтерфейсу)
    def setUp(self):
        self.client = app.test_client()

    def test_index_post(self):
        # Мок інпуту
        response = self.client.post('/', data={
            'ips': '127.0.0.1',
            'start_port': '1',
            'end_port': '1024'
        })

        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Scan Results', response.data)

if __name__ == '__main__':
    unittest.main()
