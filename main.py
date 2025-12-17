"""Passive link monitor for FTP/ethernet traffic (Linux-friendly).

The script samples interface counters, TCP retrans totals, and CRC errors
without injecting traffic. Useful to watch live while FTP runs.
"""

import argparse
import json
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import psutil


def pick_default_interface() -> str:
	"""Pick the first non-loopback interface with activity, else first non-loopback."""
	for name, counters in psutil.net_io_counters(pernic=True).items():
		if name.lower() not in {"lo", "loopback", "lo0"} and counters.bytes_sent + counters.bytes_recv > 0:
			return name
	for name in psutil.net_io_counters(pernic=True):
		if name.lower() not in {"lo", "loopback", "lo0"}:
			return name
	raise RuntimeError("No non-loopback interfaces found")


def read_int(path: Path) -> Optional[int]:
	try:
		return int(path.read_text().strip())
	except (FileNotFoundError, ValueError):
		return None


def get_crc_errors(iface: str) -> Optional[int]:
	return read_int(Path("/sys/class/net") / iface / "statistics" / "rx_crc_errors")


def parse_ss_retrans() -> Optional[int]:
	"""Return total TCP retransmissions from ss -s, if available."""
	try:
		out = subprocess.check_output(["ss", "-s"], text=True)
	except (subprocess.CalledProcessError, FileNotFoundError):
		return None
	for line in out.splitlines():
		if "retrans" in line.lower():
			parts = line.replace(",", " ").split()
			for part in parts:
				if "retrans:" in part:
					try:
						return int(part.split(":", 1)[1].split("/", 1)[0])
					except ValueError:
						return None
	return None


def diff_stats(prev, curr, interval: float) -> Dict[str, float]:
	delta_bytes_recv = curr.bytes_recv - prev.bytes_recv
	delta_bytes_sent = curr.bytes_sent - prev.bytes_sent
	delta_packets_recv = curr.packets_recv - prev.packets_recv
	delta_packets_sent = curr.packets_sent - prev.packets_sent
	return {
		"rx_mbps": (delta_bytes_recv * 8) / 1_000_000 / interval,
		"tx_mbps": (delta_bytes_sent * 8) / 1_000_000 / interval,
		"rx_pps": delta_packets_recv / interval,
		"tx_pps": delta_packets_sent / interval,
		"drop_in": curr.dropin - prev.dropin,
		"drop_out": curr.dropout - prev.dropout,
		"err_in": curr.errin - prev.errin,
		"err_out": curr.errout - prev.errout,
	}


def format_line(ts: datetime, iface: str, rates: Dict[str, float], crc: Optional[int], retrans: Optional[int]) -> str:
	parts = [
		ts.strftime("%Y-%m-%d %H:%M:%S"),
		f"iface={iface}",
		f"rx_mbps={rates['rx_mbps']:.3f}",
		f"tx_mbps={rates['tx_mbps']:.3f}",
		f"rx_pps={rates['rx_pps']:.1f}",
		f"tx_pps={rates['tx_pps']:.1f}",
		f"drop_in={rates['drop_in']}",
		f"drop_out={rates['drop_out']}",
		f"err_in={rates['err_in']}",
		f"err_out={rates['err_out']}",
	]
	if crc is not None:
		parts.append(f"rx_crc_errors={crc}")
	if retrans is not None:
		parts.append(f"tcp_retrans_total={retrans}")
	return " ".join(parts)


def main():
	parser = argparse.ArgumentParser(description="Passive link monitor for FTP data paths")
	parser.add_argument("--iface", help="Interface to monitor (default: first non-loopback)")
	parser.add_argument("--interval", type=float, default=1.0, help="Sampling interval seconds")
	parser.add_argument("--log", type=Path, help="Optional path to append JSON lines")
	args = parser.parse_args()

	iface = args.iface or pick_default_interface()
	counters = psutil.net_io_counters(pernic=True)
	if iface not in counters:
		raise SystemExit(f"Interface {iface} not found; available: {', '.join(counters)}")

	prev = counters[iface]
	print(f"Monitoring {iface} every {args.interval}s; Ctrl+C to stop")

	try:
		while True:
			time.sleep(args.interval)
			counters = psutil.net_io_counters(pernic=True)
			curr = counters[iface]
			rates = diff_stats(prev, curr, args.interval)
			crc_now = get_crc_errors(iface)
			retrans_now = parse_ss_retrans()

			line = format_line(datetime.now(), iface, rates, crc_now, retrans_now)
			print(line)

			if args.log:
				payload = {
					"ts": datetime.utcnow().isoformat(),
					"iface": iface,
					**rates,
					"rx_crc_errors": crc_now,
					"tcp_retrans_total": retrans_now,
				}
				args.log.parent.mkdir(parents=True, exist_ok=True)
				with args.log.open("a", encoding="utf-8") as fh:
					fh.write(json.dumps(payload) + "\n")

			prev = curr
	except KeyboardInterrupt:
		print("\nStopped")


if __name__ == "__main__":
	main()
