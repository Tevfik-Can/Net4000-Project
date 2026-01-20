# Cross-Layer Network Observability Project

## Structure
- `data_collection/` - HTTP client/server for application metrics
- `analysis/` - Test scripts and data analysis
- `ebpf_programs/` - eBPF headers and programs
- `results/` - Output data (gitignored)

## Quick Test
```bash
cd analysis
python3 simple_test.py
