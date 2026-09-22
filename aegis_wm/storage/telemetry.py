"""Telemetry storage managing Parquet serialization and fast querying via PyArrow / DuckDB."""

from pathlib import Path
from typing import Any, Dict, List, Optional
import duckdb
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq
from aegis_wm.schemas.flow import BidirectionalFlow
from aegis_wm.schemas.state import NetworkWindowState


class TelemetryStore:
    """Handles high-throughput Parquet storage and analytical queries on telemetry."""

    def __init__(self, base_dir: Path | str = "data"):
        self.base_dir = Path(base_dir)
        self.raw_dir = self.base_dir / "raw"
        self.interim_dir = self.base_dir / "interim"
        self.processed_dir = self.base_dir / "processed"
        for d in [self.raw_dir, self.interim_dir, self.processed_dir]:
            d.mkdir(parents=True, exist_ok=True)

    def save_flows_parquet(self, flows: List[BidirectionalFlow], output_path: Path | str) -> str:
        """Serializes list of BidirectionalFlow objects to a versioned Parquet file."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        records = [f.model_dump() for f in flows]
        # Flatten nested provenance dict for efficient tabular storage
        for r in records:
            prov = r.pop("provenance", {})
            for k, v in prov.items():
                r[f"prov_{k}"] = v

        df = pd.DataFrame(records)
        table = pa.Table.from_pandas(df)
        pq.write_table(table, str(out), compression="snappy")
        return str(out)

    def load_flows_dataframe(self, parquet_path: Path | str) -> pd.DataFrame:
        """Loads flows from Parquet into a Pandas DataFrame."""
        return pd.read_parquet(str(parquet_path))

    def save_states_parquet(self, states: List[NetworkWindowState], output_path: Path | str) -> str:
        """Serializes network window states to Parquet."""
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        records = []
        for s in states:
            d = s.model_dump()
            prov = d.pop("provenance", {})
            for k, v in prov.items():
                d[f"prov_{k}"] = v
            # edges stored as json string or count
            d["edge_count"] = len(d.pop("edges", []))
            # feature vector stored as list
            records.append(d)

        df = pd.DataFrame(records)
        table = pa.Table.from_pandas(df)
        pq.write_table(table, str(out), compression="snappy")
        return str(out)

    def load_states_dataframe(self, parquet_path: Path | str) -> pd.DataFrame:
        """Loads window states from Parquet."""
        return pd.read_parquet(str(parquet_path))

    def query_flows(
        self,
        parquet_path: Path | str,
        sql_filter: str = "1=1",
        limit: int = 1000,
        offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Executes fast SQL query over flow Parquet using DuckDB."""
        p = str(Path(parquet_path).resolve()).replace("\\", "/")
        query = f"""
            SELECT * FROM read_parquet('{p}')
            WHERE {sql_filter}
            ORDER BY start_timestamp ASC
            LIMIT {limit} OFFSET {offset}
        """
        con = duckdb.connect()
        try:
            res_df = con.execute(query).fetchdf()
            return res_df.to_dict(orient="records")
        finally:
            con.close()
