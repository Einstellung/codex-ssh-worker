import io
import zipfile

import pytest

from codex_worker.exports import ExportBlocked, ExportGuard
from codex_worker.privacy import Redactor


@pytest.mark.parametrize('text', [
    'wrote hello.txt, pilot.tar and train.py', 'model.pt best.ckpt net.onnx weights.bin',
    'config.yaml results.csv run.log archive.tar.gz', 'os.path.join and self.settings.get',
    'torch==9.20.0.48', 'pip install pkg>=13.0.88.1', 'Driver Version: 595.58.03',
    'CUDA 13.0.88.1', 'cuda-12.4.0.1 runtime', 'version 1.2.3.4', 'v10.0.0.1',
    'firmware 2.0.1.7', '1.2.3.4.5 is a five-part version', 'Python 3.12.3',
])
def test_versions_and_filenames_are_not_rewritten(text):
    assert Redactor().text(text) == text


@pytest.mark.parametrize('text, secret', [
    ('connect to 192.0.2.10 now', '192.0.2.10'), ('ssh user@198.51.100.7.', '198.51.100.7'),
    ('route 203.0.113.0/24', '203.0.113.0'), ('13.0.88.1', '13.0.88.1'),
    ('build at 203.0.113.9', '203.0.113.9'), ('(192.0.2.44)', '192.0.2.44'),
    ('see worker.example.net.', 'worker.example.net'), ('api.example.com:443', 'api.example.com'),
    ('gpu01.lab.internal', 'gpu01.lab.internal'), ('box.example.invalid', 'box.example.invalid'),
    ('node.corp up', 'node.corp'),
])
def test_real_addresses_and_domains_are_still_redacted(text, secret):
    output = Redactor().text(text)
    assert secret not in output
    assert '[redacted-' in output


def test_policy_suffixes_and_literals_extend_matching():
    assert 'node.cluster' in Redactor().text('node.cluster')
    assert 'node.cluster' not in Redactor(host_suffixes=['cluster']).text('node.cluster')
    assert 'bare-machine' not in Redactor(['bare-machine']).text('ran on bare-machine')
    # A file extension can never be configured as a hostname suffix.
    assert Redactor(host_suffixes=['txt']).text('hello.txt') == 'hello.txt'


def test_export_guard_allows_versions_but_holds_addresses():
    guard = ExportGuard(Redactor())
    guard.check_text('torch==9.20.0.48 driver 595.58.03 CUDA 13.0.88.1 train.py')
    with pytest.raises(ExportBlocked):
        guard.check_text('endpoint 192.0.2.9')
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr('pilot.tar', b'versions torch==9.20.0.48')
    ExportGuard(Redactor()).scan(data)
