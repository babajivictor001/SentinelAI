from src.analyzer import analyze_logs
from src.threat_engine import calculate_risk
from src.report_generator import generate_report

file = open("logs/sample_log.txt", "r")

results = analyze_logs(file)

file.close()

risk = calculate_risk(results)

generate_report(results, risk)