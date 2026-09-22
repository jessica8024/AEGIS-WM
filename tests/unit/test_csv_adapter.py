"""Unit tests for CIC-IDS-2017 CSV ingestion adapter."""

from pathlib import Path
import tempfile
import pandas as pd
import pytest
from aegis_wm.ingestion.csv_adapter import CICFlowCSVAdapter


def test_csv_adapter_synthetic_sample():
    with tempfile.TemporaryDirectory() as tmpdir:
        csv_file = Path(tmpdir) / "sample_flow.csv"
        # Synthetic CIC-style CSV
        df = pd.DataFrame({
            " Destination Port": [80, 443, 22],
            " Flow Duration": [1000000, 2000000, 500000],
            " Total Fwd Packets": [5, 10, 2],
            " Total Backward Packets": [4, 8, 1],
            "Total Length of Fwd Packets": [500, 1200, 100],
            " Total Length of Bwd Packets": [800, 2400, 50],
            " Flow Packets/s": [9.0, 9.0, 6.0],
            "Flow Bytes/s": [1300.0, 1800.0, 300.0],
            "SYN Flag Count": [1, 1, 1],
            "ACK Flag Count": [1, 1, 0],
            "RST Flag Count": [0, 0, 1],
            " Label": ["BENIGN", "BENIGN", "PortScan"],
        })
        df.to_csv(csv_file, index=False)

        adapter = CICFlowCSVAdapter()
        flows, report = adapter.process_csv(csv_file)

        assert len(flows) == 3
        assert report.valid_flows_extracted == 3
        assert flows[0].dst_port == 80
        assert flows[1].dst_port == 443
        assert flows[2].dst_port == 22
        assert flows[2].source_label == "PortScan"
        assert flows[0].provenance.source_file_hash != ""


def test_csv_adapter_authentic_data_if_present():
    authentic_path = Path(
        r"C:\Users\Sathish-PhD\Downloads\MachineLearningCSV\CIC-IDS- 2017\Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    )
    if not authentic_path.exists():
        pytest.skip("Authentic CIC-IDS-2017 PortScan CSV not found on host machine.")

    adapter = CICFlowCSVAdapter()
    # Read first 100 rows of authentic PortScan data
    flows, report = adapter.process_csv(authentic_path, max_rows=100)

    assert len(flows) == 100
    assert report.valid_flows_extracted == 100
    assert flows[0].provenance.source_file_hash != ""
    assert flows[0].src_ip_pseudo.startswith("host_")
