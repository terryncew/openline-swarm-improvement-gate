from olp_swarm_gate.successor_benchmark import run_frozen_benchmark

report = run_frozen_benchmark()
print(report["decision_counts"])
print("PASS" if report["passed"] else "FAIL")
