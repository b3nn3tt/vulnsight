# Global Views

Global commands look across all visible scans and use the latest completed run from each scan. They are useful when you want a portfolio-style view rather than the currently selected scan context.

Run global help with:

```bash
python3 main.py global --help
```

## Summary

```bash
python3 main.py global summary
```

The summary shows how many scans are available, how many latest completed runs were included, and severity counts across the aggregated findings.

Useful filters and ranking options:

```bash
python3 main.py global summary --min-severity high
python3 main.py global summary --top-risks severity
python3 main.py global summary --top-risks volume
python3 main.py global summary --top-risks weighted --limit 20
```

Top risk modes are:

- `severity`: rank by severity first, then instance count.
- `volume`: rank by total instances across scans.
- `weighted`: rank by severity weight squared multiplied by instance count.

## Findings

```bash
python3 main.py global findings
```

This groups findings by plugin ID across all latest completed scan runs.

Useful filters:

```bash
python3 main.py global findings --min-severity high
python3 main.py global findings --severity critical
python3 main.py global findings --only confirmed
python3 main.py global findings --exclude false_positive
```

CSV output is written to stdout:

```bash
python3 main.py global findings --format csv > global-findings.csv
```

## One Finding Across Scans

```bash
python3 main.py global finding 19506
```

This shows where a plugin appears across all latest completed scan runs, including affected scans, hosts, validation status, description, solution, and available evidence.

You can combine it with a minimum severity filter:

```bash
python3 main.py global finding 19506 --min-severity high
```

## Notes

Global views can be slower than scan-local views because they fetch data from each visible scan. If global commands feel slow, run `python3 main.py scans --details` to check for scans with unusually slow or unhealthy histories.
