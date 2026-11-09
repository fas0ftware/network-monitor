import socket
import unittest
from unittest import mock

import portscan


class PortScanTests(unittest.TestCase):
    def test_open_and_closed_ports_on_localhost(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        open_port = server.getsockname()[1]

        closed = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        closed.bind(("127.0.0.1", 0))
        closed_port = closed.getsockname()[1]
        closed.close()  # nothing listens here anymore

        try:
            result = portscan.scan_ports("127.0.0.1", ports=[open_port, closed_port])
        finally:
            server.close()

        self.assertEqual([port for port, _service in result], [open_port])

    def test_service_name_lookup_and_fallback(self):
        # The system's /etc/services differs between machines, so fake it.
        with mock.patch.object(portscan.socket, "getservbyport", return_value="ssh"):
            self.assertEqual(portscan.get_service_name(22), "ssh")
        with mock.patch.object(portscan.socket, "getservbyport", side_effect=OSError):
            self.assertEqual(portscan.get_service_name(62078), "unknown")

    def test_risky_ports_are_part_of_the_common_list(self):
        self.assertTrue(portscan.RISKY_PORTS <= set(portscan.COMMON_PORTS))


if __name__ == "__main__":
    unittest.main()
