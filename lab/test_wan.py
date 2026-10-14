import base64
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from wan import credentials, json_lines
from remote import SANITIZER


class WANPreparationTests(unittest.TestCase):
    def test_temporary_credentials_match_wire_byte_lengths_and_identity(self):
        server,client=credentials()
        self.assertEqual(server['admission'],client['admission'])
        self.assertEqual(server['allowed_clients'],[client['public']])
        self.assertEqual(client['server_public'],server['public'])
        for side in (server,client):
            self.assertEqual(len(base64.b64decode(side['admission'])),32)
            private=X25519PrivateKey.from_private_bytes(base64.b64decode(side['private']))
            public=private.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)
            self.assertEqual(public,base64.b64decode(side['public']))
        raw=json.dumps({'credentials':server,'client':client})
        cleaned=SANITIZER.text(raw)
        for value in (server['admission'],server['private'],server['public'],client['private'],client['public']):
            self.assertNotIn(value,cleaned)

    def test_fixture_log_parsing_keeps_only_json_observations(self):
        text='non-json diagnostic\n{"event":"target_open","opened":1}\n{truncated\n{"event":"target_open","opened":2}\n'
        rows=json_lines(text)
        self.assertEqual([r['opened'] for r in rows],[1,2])


if __name__=='__main__':
    unittest.main()
