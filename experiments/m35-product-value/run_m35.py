#!/usr/bin/env python3
"""Frozen M3.5 controller. Repository code runs only in AutoCage's sandbox."""
from __future__ import annotations
import argparse, copy, hashlib, importlib.util, json, os, platform, shutil, socket, statistics, subprocess, sys, time
from pathlib import Path

HERE = Path(__file__).resolve().parent
M3 = HERE.parent / "real-repository-v1"
PROTOCOL = json.loads((HERE / "PROTOCOL.json").read_text())
WORKFLOWS = json.loads((HERE / "workflows.json").read_text())
SOURCE_ROOT = Path("/tmp/autocage-real-repository-v1/workspaces")
PROJECT = HERE.parents[1] / "project"
TIMEOUT = 120
M3_MODULE = None

def sha(data): return hashlib.sha256(data).hexdigest()

def load_m3(root):
    spec = importlib.util.spec_from_file_location("autocage_m3_controller", M3 / "run_benchmark.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    module.WORK_ROOT = root
    return module

def validate(binary):
    if PROTOCOL["status"] != "frozen-before-final-comparison":
        raise RuntimeError("M3.5 protocol is not frozen")
    pins = {
        "workflow_manifest_sha256": sha((HERE / "workflows.json").read_bytes()),
        "controller_sha256": sha(Path(__file__).read_bytes()),
        "rr03_diagnostic_sha256": sha((HERE / "diagnose_rr03.py").read_bytes()),
        "autocage_release_binary_sha256": sha(binary.read_bytes()),
        "historical_m3_protocol_sha256": sha((M3 / "protocol.json").read_bytes()),
        "cargo_manifest_sha256": sha((PROJECT / "Cargo.toml").read_bytes()),
        "cargo_lock_sha256": sha((PROJECT / "Cargo.lock").read_bytes()),
        "optimizer_test_source_sha256": sha((PROJECT / "src/optimizer.rs").read_bytes()),
    }
    for key, actual in pins.items():
        if PROTOCOL.get(key) != actual: raise RuntimeError(f"frozen input mismatch: {key}")
    toolchain={"rustc":subprocess.run(["rustc","--version"],text=True,capture_output=True,check=True).stdout.strip(),"cargo":subprocess.run(["cargo","--version"],text=True,capture_output=True,check=True).stdout.strip()}
    if PROTOCOL.get("rust_toolchain")!=toolchain: raise RuntimeError("Rust build toolchain differs from frozen protocol")
    old = json.loads((M3 / "protocol.json").read_text())
    for path, key in [("tasks.json","tasks_sha256"),("prepare.py","prepare_sha256"),("run_benchmark.py","runner_sha256"),("setup/python-requirements.lock","python_lock_sha256"),("setup/install-python-runtime.sh","runtime_setup_sha256")]:
        if sha((M3 / path).read_bytes()) != old[key]: raise RuntimeError(f"historical M3 input changed: {path}")
    prepared = M3 / "fixtures/prepared-manifest.json"
    if sha(prepared.read_bytes()) != old["prepared_manifest_sha256"]: raise RuntimeError("prepared M3 fixtures changed")
    import importlib.metadata
    installed = {d.metadata.get("Name", "").lower().replace("_", "-"):d.version for d in importlib.metadata.distributions(path=["/usr/local/lib/autocage-m3-site-v2"]) if d.metadata.get("Name")}
    for name, version in old["python_packages"].items():
        if installed.get(name.lower().replace("_", "-")) != version: raise RuntimeError(f"Python runtime drift: {name}")
    for package, version in old["apt_packages"].items():
        actual=subprocess.run(["dpkg-query","-W","-f=${Version}",package],text=True,capture_output=True,check=True).stdout.strip()
        if actual != version: raise RuntimeError(f"Ubuntu runtime drift: {package}")
    return old

def extend_m3(m3):
    marker = '    else:\n        raise SystemExit("unknown fixture operation")\n'
    replacement = '''    elif kind == "compileall":
        import compileall
        import py_compile
        if not compileall.compile_dir(str(Path("/workspace") / operation["directory"]), quiet=1, force=True, invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH): raise SystemExit(41)
    elif kind == "source-archive":
        import tarfile
        source = Path("/workspace") / operation["directory"]
        output_path = Path("/workspace") / operation["output"]
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with tarfile.open(output_path, "w", format=tarfile.GNU_FORMAT) as archive:
            for entry in sorted(source.rglob("*"), key=lambda item: item.relative_to(source.parent).as_posix()):
                info = archive.gettarinfo(str(entry), arcname=entry.relative_to(source.parent).as_posix())
                info.mtime=0; info.uid=0; info.gid=0; info.uname=""; info.gname=""
                if entry.is_file() and not entry.is_symlink():
                    with entry.open("rb") as stream: archive.addfile(info, stream)
                else: archive.addfile(info)
    else:
        raise SystemExit("unknown fixture operation")
'''
    if marker not in m3.AGENT_SCRIPT: raise RuntimeError("M3 agent extension point changed")
    m3.AGENT_SCRIPT = m3.AGENT_SCRIPT.replace(marker, replacement)
    original_specs = m3.command_specs
    ops = {row["task_id"]: row["operations"] for row in WORKFLOWS["workflows"]}
    contexts = {}
    def specs(task, metadata, workspace, host_canary, port):
        task2 = dict(task)
        task2["operations"] = list(task.get("operations", [])) + ops[task["id"]]
        result = original_specs(task2, metadata, workspace, host_canary, port)
        contexts[task["id"]] = {"agent": result[0], "verifier": result[1], "host_canary": host_canary, "port": port}
        return result
    m3.command_specs = specs
    parent = m3.LoopbackCanary
    held = []
    class HeldCanary(parent):
        def __init__(self):
            super().__init__()
            held.append(self)
        def close(self): pass
        def finish(self):
            if self.listener.fileno() >= 0: parent.close(self)
    m3.LoopbackCanary = HeldCanary
    return contexts, held, HeldCanary

def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")

def read_contract(run):
    return json.loads((run / "contract.json").read_text())

def execution_identity(contract):
    return {k:v for k,v in contract.items() if k != "authorized_ceiling"}

def unrelated_source_path(workspace,task):
    changed=set(task.get("patch_paths",[]))
    candidates=[p for p in sorted((workspace/"src").rglob("*.py")) if p.is_file() and not p.is_symlink() and p.relative_to(workspace).as_posix() not in changed]
    if not candidates: raise RuntimeError(f"no unmodified Python source is available for drift control: {task['id']}")
    return candidates[0]

def attack_run(m3, binary, workspace, run_dir, grants, target):
    script = "from pathlib import Path; import sys; p=Path('/workspace')/sys.argv[1]; p.parent.mkdir(parents=True,exist_ok=True); p.open('xb').write(b'AUTOCAGE-M35-STAGE-CANARY\\\\n')"
    argv = ["run","--workspace",str(workspace),"--run-dir",str(run_dir),"--timeout-seconds","10"]
    run_dir.parent.mkdir(parents=True, exist_ok=True)
    m3.add_run_policy_args(argv, grants)
    argv += ["--","/usr/bin/python3","-c",script,target]
    return m3.run_cli(binary, argv, 90)

def high_impact(path):
    p=path.lower()
    return any(p == x or p.startswith(x) for x in (".github/workflows/","deploy/","deployment/","infra/","scripts/","package.json","pyproject.toml","cargo.toml"))

def covered(path, grants):
    p=Path(path)
    return any((g["kind"]=="file_contents" and p==Path(g["path"])) or (g["kind"]=="directory_tree" and (Path(g["path"])==Path(".") or p==Path(g["path"]) or p.is_relative_to(Path(g["path"])))) for g in grants)

def shape(m3, grants, root):
    base=m3.cost(grants,root)
    recursive=sorted(g["path"] for g in grants if g["kind"]=="directory_tree")
    files=sorted(g["path"] for g in grants if g["kind"]=="file_contents")
    hi=sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file() and not p.is_symlink() and high_impact(p.relative_to(root).as_posix()) and covered(p.relative_to(root).as_posix(),grants))
    breadth=[{"path":p,"immediate_children":len(list((root if p=="." else root/p).iterdir()) ) if (root if p=="." else root/p).is_dir() else None} for p in recursive]
    return {"weighted_write_surface_v1":base,"exact_file_grants":files,"recursive_directory_grants":recursive,"existing_files_covered":base["writable_regular_files"],"existing_directory_entries_covered":base["writable_directories"],"grant_depths":[0 if p=="." else len(Path(p).parts) for p in recursive],"grant_breadth":breadth,"high_impact_files_covered":hi,"future_child_creation_allowed":bool(recursive),"future_child_scope":"unbounded under each recursive grant" if recursive else "none"}

def phase_totals(root):
    records=[]
    for p in root.rglob("run.json"):
        try: records.append((p.relative_to(root).as_posix(),json.loads(p.read_text())))
        except (OSError,json.JSONDecodeError): pass
    fields=("preflight_elapsed_millis","workspace_stage_elapsed_millis","policy_validation_elapsed_millis","agent_backend_compile_elapsed_millis","verifier_backend_compile_elapsed_millis","readonly_canary_backend_compile_elapsed_millis","supervisor_elapsed_before_record_millis")
    buckets={"initial_broad":[],"optimizer_replays":[],"exact_repeats":[],"other_baselines_and_canaries":[]}
    for path,record in records:
        if path.startswith("A-broad/"): buckets["initial_broad"].append(record)
        elif "/tuning/replays/" in path: buckets["optimizer_replays"].append(record)
        elif path.startswith("exact-repeats/"): buckets["exact_repeats"].append(record)
        else: buckets["other_baselines_and_canaries"].append(record)
    def summarize(items):
        return {field:{"total_millis":sum(r.get("phase_timings",{}).get(field,0) or 0 for r in items),"records":sum(field in r.get("phase_timings",{}) for r in items)} for field in fields}
    return {"run_record_count":len(records),"phase_totals_by_execution_class":{name:summarize(items) for name,items in buckets.items()},"timing_note":"Bubblewrap argv construction excludes process start, kernel mount setup, and syscall overhead."}

def drift_study(m3,binary,debug,task,root,context):
    workspace=root/"workspaces"/task["id"]
    base=root/"runs"/task["id"]/"A-broad"
    original_contract=read_contract(base)
    original_tree=m3.tree_digest(workspace)
    testfile=next(p for p in sorted((workspace/task["verifier_root"]).rglob("*.py")) if p.is_file())
    test_bytes=testfile.read_bytes()
    unrelated_file=unrelated_source_path(workspace,task)
    pyproject=workspace/"pyproject.toml"
    py_bytes=pyproject.read_bytes()
    agent,verifier=context["agent"],context["verifier"]
    cases=[]
    def mutate_file(path,data):
        before=path.read_bytes() if path.exists() else None
        path.parent.mkdir(parents=True,exist_ok=True); path.write_bytes(data)
        return lambda: path.unlink() if before is None else path.write_bytes(before)
    def case(name, *, change=None, ag=None, ve=None, exe=binary):
        run=root/"contract-drift"/task["id"]/name
        run.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(base,run,symlinks=True)
        undo=change() if change else None
        try:
            out=m3.tune(exe,run,workspace,ag or agent,ve or verifier,"hierarchical",TIMEOUT)
            trials=run/"tuning"/"replays"
            count=len(list(trials.glob("trial-*"))) if trials.exists() else 0
            cases.append({"change":name,"return_code":out["return_code"],"rejected":out["return_code"]!=0,"error_tail":out.get("stderr","")[-500:],"replay_count":count,"rejected_before_replay":out["return_code"]!=0 and count==0,"optimizer_record_created":(run/"optimizer.json").exists()})
        finally:
            if undo: undo()
    case("unrelated-source-comment",change=lambda:mutate_file(unrelated_file,unrelated_file.read_bytes()+b"\n# m35 unrelated source comment\n"))
    case("added-source-file",change=lambda:mutate_file(workspace/"src/autocage_m35_added.py",b"# drift\nVALUE=1\n"))
    case("modified-verifier-test",change=lambda:mutate_file(testfile,test_bytes+b"\n# drift\n"))
    case("build-configuration-change",change=lambda:mutate_file(pyproject,py_bytes+b"\n# m35 build config drift\n"))
    case("dependency-declaration-addition",change=lambda:mutate_file(workspace/"requirements-autocage-m35.txt",b"autocage-m35-synthetic==0.0.1\n"))
    case("changed-agent-argv",ag=[agent[0],"-X","utf8",*agent[1:]])
    case("changed-verifier-argv",ve=[verifier[0],"-X","utf8",*verifier[1:]])
    if debug.is_file(): case("runtime-binary-fingerprint-change",exe=debug)
    if m3.tree_digest(workspace)!=original_tree or testfile.read_bytes()!=test_bytes or pyproject.read_bytes()!=py_bytes:
        raise RuntimeError("contract drift mutations were not restored")
    return {"task_id":task["id"],"unrelated_source_path":unrelated_file.relative_to(workspace).as_posix(),"contract_schema_version":original_contract.get("schema_version"),"cases":cases,"all_rejected_before_replay":bool(cases) and all(c["rejected_before_replay"] for c in cases),"source_restored_exactly":True}

def shadow_study(m3,binary,task,policy,root):
    base=root/"workspaces"/task["id"]
    fixture=json.loads((M3/"fixtures"/task["id"]/"fixture.json").read_text())
    mutations=[
        ("unrelated-source-comment",lambda w:(unrelated_source_path(w,task).write_bytes(unrelated_source_path(w,task).read_bytes()+b"\n# m35 unrelated source comment\n")),"source"),
        ("added-source-file",lambda w:(w/"src/autocage_m35_added.py").write_text("# shadow\nVALUE=1\n"),"source"),
        ("modified-test-comment",lambda w:(next((w/task["verifier_root"]).rglob("*.py")).write_bytes(next((w/task["verifier_root"]).rglob("*.py")).read_bytes()+b"\n# shadow\n")),"source"),
        ("build-config-comment",lambda w:(w/"pyproject.toml").write_bytes((w/"pyproject.toml").read_bytes()+b"\n# shadow\n"),"source"),
        ("dependency-declaration-addition",lambda w:(w/"requirements-autocage-m35.txt").write_text("autocage-m35-synthetic==0.0.1\n"),"source"),
        ("changed-agent-argv",lambda w:None,"agent"),
        ("changed-verifier-argv",lambda w:None,"verifier"),
    ]
    results=[]
    for i,(name,mutate,change_kind) in enumerate(mutations):
        ws=root/"shadow-workspaces"/name
        ws.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(base,ws,symlinks=True); mutate(ws)
        host=root/"canaries"/f"shadow-{i}.txt"; host.write_text("AUTOCAGE-M35-HOST-CANARY\n")
        listener=m3.LoopbackCanary()
        agent,verifier=m3.command_specs(task,fixture,ws,host,listener.port)
        if change_kind=="agent": agent=[agent[0],"-X","utf8",*agent[1:]]
        if change_kind=="verifier": verifier=[verifier[0],"-X","utf8",*verifier[1:]]
        shadow_run=root/"stale-policy-shadows"/name
        shadow_run.parent.mkdir(parents=True, exist_ok=True)
        out=m3.make_run(binary,ws,shadow_run,task,agent,verifier,policy,TIMEOUT,False)
        rec=out.get("record")
        check=m3.security_outcome(rec,listener,host,ws,m3.tree_digest(ws),ws/task["verifier_root"],m3.content_tree_digest(ws/task["verifier_root"]))
        results.append({"change":name,"utility_pass":bool(rec and rec.get("outcome")=="verified"),"security":check,"promoted":False,"contract_recorded":False})
        listener.finish()
    return {"source_task":task["id"],"policy":policy,"cases":results,"note":"Research-only shadow; does not authorize cross-contract reuse."}

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--autocage",type=Path,default=Path("/tmp/autocage-m35/project/target/release/autocage"))
    parser.add_argument("--debug-autocage",type=Path,default=Path("/tmp/autocage-m35/project/target/debug/autocage"))
    parser.add_argument("--work-root",type=Path,default=Path("/tmp/autocage-m35"))
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    binary=args.autocage.resolve(); debug=args.debug_autocage.resolve()
    old_protocol=validate(binary)
    if not args.output.is_absolute() or args.output.exists(): raise RuntimeError("output must be a new absolute directory")
    root=args.work_root.resolve()
    if (root/"workspaces").exists() or (root/"runs").exists(): raise RuntimeError("M3.5 root must be fresh")
    m3=load_m3(root)
    global M3_MODULE
    M3_MODULE=m3
    contexts,held,_=extend_m3(m3)
    tasks=json.loads((M3/"tasks.json").read_text())["tasks"]
    by_id={t["id"]:t for t in tasks}
    selected=[by_id[w["task_id"]] for w in WORKFLOWS["workflows"]]
    (root/"workspaces").mkdir(parents=True)
    for task in selected:
        src=SOURCE_ROOT/task["id"]; dest=root/"workspaces"/task["id"]
        shutil.copytree(src,dest,symlinks=True)
        fixture=json.loads((M3/"fixtures"/task["id"]/"fixture.json").read_text())
        if m3.tree_digest(dest)!=fixture["input_tree_sha256"]: raise RuntimeError(f"snapshot mismatch: {task['id']}")
    started=time.monotonic()
    rows=[]
    for i,task in enumerate(selected):
        print(f"M3.5 {i+1}/{len(selected)} {task['id']}",flush=True)
        row=m3.task_run(binary,task,i)
        row["m35_workflow_operations"]=next(w["operations"] for w in WORKFLOWS["workflows"] if w["task_id"]==task["id"])
        row["outcome_distinction"]={"broad_task_utility_pass":bool(row.get("baseline_A",{}).get("utility_pass")),"F_narrow_policy_validated":row.get("optimizers",{}).get("F",{}).get("status")=="validated","F_result":"validated narrower policy" if row.get("optimizers",{}).get("F",{}).get("status")=="validated" else ("known successful broad ceiling retained; optimization inconclusive" if row.get("baseline_A",{}).get("utility_pass") else "broad task itself did not verify")}
        ws=root/"workspaces"/task["id"]; taskroot=root/"runs"/task["id"]
        fixture=json.loads((M3/"fixtures"/task["id"]/"fixture.json").read_text())
        host=Path(contexts[task["id"]]["host_canary"])
        canary=held[-1]
        source_hash=m3.tree_digest(ws); verifier_root=ws/task["verifier_root"]; verifier_hash=m3.content_tree_digest(verifier_root)
        # F is used only when the production seal-inspecting path verifies a validated candidate.
        fdir=taskroot/"F-hierarchical"
        inspected=m3.run_cli(binary,["inspect",str(fdir)],30)
        fvalue=row["optimizers"]["F"]
        try:
            inspected_json=json.loads(inspected.get("stdout",""))
        except json.JSONDecodeError:
            inspected_json={}
        seal_ok=(inspected["return_code"]==0 and inspected_json.get("validation")=="SEALED" and inspected_json.get("reusable_policy") is True and (inspected_json.get("optimization") or {}).get("status")=="validated")
        repeats={"B":[],"F":[]}
        if row["baseline_A"]["utility_pass"]:
            baseline_contract=read_contract(taskroot/"A-broad")
            repeat_methods=[("B",row["baselines"]["B"]["policy"])]
            if seal_ok and fvalue["status"]=="validated":
                repeat_methods.append(("F",fvalue["policy"]))
            for label,grants in repeat_methods:
                for repeat in range(1,4):
                    rd=taskroot/"exact-repeats"/label/f"repeat-{repeat}"
                    rd.parent.mkdir(parents=True, exist_ok=True)
                    out=m3.make_run(binary,ws,rd,task,contexts[task["id"]]["agent"],contexts[task["id"]]["verifier"],grants,TIMEOUT,True)
                    rec=out.get("record")
                    security=m3.security_outcome(rec,canary,host,ws,source_hash,verifier_root,verifier_hash) if rec else {"status":"NOT_TESTED"}
                    c=read_contract(rd) if (rd/"contract.json").is_file() else {}
                    repeats[label].append({"repeat":repeat,"utility_pass":bool(rec and rec.get("outcome")=="verified"),"security":security,"cli_wall_seconds":out["elapsed_seconds"],"agent_seconds":(rec or {}).get("agent",{}).get("elapsed_millis",0)/1000,"verifier_seconds":((rec or {}).get("verifier") or {}).get("elapsed_millis",0)/1000,"execution_identity_matches":bool(c) and execution_identity(c)==execution_identity(baseline_contract),"policy":grants})
        row["exact_contract_repeats"]=repeats
        row["optimizer_seal_inspection"]={"return_code":inspected["return_code"],"validation":inspected_json.get("validation","NOT TESTED"),"reusable_policy":inspected_json.get("reusable_policy",False),"accepted_for_repeat":seal_ok,"stderr":inspected.get("stderr","")[-500:]}
        policies={"A":row["baseline_A"]["policy"],"B":row["baselines"]["B"]["policy"],"C":row["baselines"]["C"]["policy"]}
        policies.update({k:row["optimizers"][k]["policy"] or [] for k in ("D","E","F")})
        attacks={}
        for label in ("A","B","C","D","E","F"):
            rel=f"{task['verifier_root']}/.autocage-m35-canary-{label.lower()}"
            rd=taskroot/"unauthorized-write"/label
            out=attack_run(m3,binary,ws,rd,policies[label],rel)
            stage=rd/"stage"/rel; rec=m3.read_record(rd)
            checks=(rec or {}).get("security_checks",[])
            required=[c for c in checks if c.get("required_for_policy_promotion")]
            exists=stage.is_file() and stage.read_bytes()==b"AUTOCAGE-M35-STAGE-CANARY\\n"
            controls=bool(rec and (rec.get("agent") or {}).get("exit_code") is not None and required and all(c["status"]=="passed" for c in required))
            expected_allow=any(g["kind"]=="directory_tree" and (g["path"]=="." or rel==g["path"] or rel.startswith(g["path"].rstrip("/")+"/")) for g in policies[label])
            observed_pass=controls and exists==expected_allow and m3.tree_digest(ws)==source_hash
            attacks[label]={"policy":policies[label],"expected_allow":expected_allow,"canary_blocked":not exists,"canary_created":exists,"status":"PASS" if observed_pass else ("FAIL" if controls else "NOT_TESTED"),"run_record_present":rec is not None,"agent_exit_code":(rec or {}).get("agent",{}).get("exit_code"),"mandatory_checks_executed_passed":bool(required) and all(c["status"]=="passed" for c in required),"original_workspace_unchanged":m3.tree_digest(ws)==source_hash,"cli_return_code":out["return_code"]}
        row["unauthorized_write_attempts"]=attacks
        base=taskroot/"A-broad"/"baseline"
        row["policy_shape"]={k:shape(m3,policies[k],base) for k in policies}
        row["timings"]=phase_totals(taskroot)
        if task["id"]=="RR01-click-short-help":
            row["contract_drift"]=drift_study(m3,binary,debug,task,root,contexts[task["id"]])
            if fvalue["status"]=="validated": row["stale_policy_shadow"]=shadow_study(m3,binary,task,fvalue["policy"],root)
            else: row["stale_policy_shadow"]={"status":"NOT TESTED","reason":"no validated F policy"}
        write_json(args.output/"tasks"/f"{task['id']}.json",row)
        rows.append(row)
        for item in list(held): item.finish(); held.remove(item)
    elapsed=time.monotonic()-started
    aggregate=summarize(rows,elapsed)
    release=os_release()
    final={"suite_id":PROTOCOL["suite_id"],"protocol_sha256":sha((HERE/"PROTOCOL.json").read_bytes()),"workflow_manifest_sha256":sha((HERE/"workflows.json").read_bytes()),"controller_sha256":sha(Path(__file__).read_bytes()),"binary_sha256":sha(binary.read_bytes()),"environment":release,"total_wall_seconds":elapsed,"aggregate":aggregate,"tasks":[r["task_id"] for r in rows],"classification":"Only controller-inspected effects and executed required checks are counted as security evidence."}
    write_json(args.output/"aggregate.json",final); write_json(args.output/"environment.json",release)
    print(json.dumps(aggregate,indent=2))
    return 0

def os_release():
    data={}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            k,v=line.split("=",1); data[k]=v.strip('"')
    m3protocol=json.loads((M3/"protocol.json").read_text())
    apt={name:subprocess.run(["dpkg-query","-W","-f=${Version}",name],text=True,capture_output=True,check=True).stdout.strip() for name in m3protocol["apt_packages"]}
    import importlib.metadata
    found={d.metadata.get("Name","").lower().replace("_","-"):d.version for d in importlib.metadata.distributions(path=["/usr/local/lib/autocage-m3-site-v2"]) if d.metadata.get("Name")}
    python={name:found[name.lower().replace("_","-")] for name in m3protocol["python_packages"]}
    rust=subprocess.run(["rustc","--version","--verbose"],text=True,capture_output=True,check=True).stdout.strip()
    cargo=subprocess.run(["cargo","--version"],text=True,capture_output=True,check=True).stdout.strip()
    return {"distribution":data.get("PRETTY_NAME"),"architecture":platform.machine(),"kernel":platform.release(),"python":platform.python_version(),"rustc":rust,"cargo":cargo,"bubblewrap":subprocess.run(["/usr/bin/bwrap","--version"],text=True,capture_output=True,check=True).stdout.strip(),"apt_package_versions":apt,"python_package_versions":python,"network":"sandbox processes use a private network namespace"}

def summarize(rows,elapsed):
    result={"workflow_count":len(rows),"baseline_A_task_utility_passes":sum(r["baseline_A"]["utility_pass"] for r in rows),"F_narrow_policy_promotions":sum(r["outcome_distinction"]["F_narrow_policy_validated"] for r in rows),"F_safe_broad_fallbacks_after_successful_broad_run":sum(r["outcome_distinction"]["broad_task_utility_pass"] and not r["outcome_distinction"]["F_narrow_policy_validated"] for r in rows),"F_broad_task_utility_failures":sum(not r["outcome_distinction"]["broad_task_utility_pass"] for r in rows),"methods":{}}
    for label in ("A","B","C","D","E","F"):
        values=[r["baseline_A"] if label=="A" else r["baselines"][label] if label in ("B","C") else r["optimizers"][label] for r in rows]
        successful=[v for v in values if v.get("utility_pass") and (label not in ("D","E","F") or v.get("status")=="validated")]
        red=[v.get("successful_task_reduction_percent") for v in successful if v.get("successful_task_reduction_percent") is not None]
        attacks=[r["unauthorized_write_attempts"][label] for r in rows]
        repeats=[x for r in rows for x in r["exact_contract_repeats"].get(label,[])]
        result["methods"][label]={"utility_passes":sum(v.get("utility_pass",False) for v in values),"validated_promotions":sum(v.get("status")=="validated" for v in values) if label in ("D","E","F") else None,"conditional_median_reduction_percent":statistics.median(red) if red else None,"full_corpus_mean_reduction_failed_or_inconclusive_zero":statistics.mean([v.get("full_corpus_reduction_percent",0) for v in values]),"full_corpus_median_reduction_failed_or_inconclusive_zero":statistics.median([v.get("full_corpus_reduction_percent",0) for v in values]),"agent_executions_including_shared_broad":sum(v.get("agent_executions_including_shared_setup",0) for v in values),"verifier_executions_including_shared_broad":sum(v.get("verifier_executions_including_shared_setup",0) for v in values),"search_replays":sum(v.get("search_replays",0) for v in values),"validation_replays":sum(v.get("fresh_validation_replays",0) for v in values),"optimizer_replays":sum(v.get("optimizer_total_replays",0) for v in values),"timeouts":sum(v.get("timeouts",0) for v in values),"unauthorized_write_attempts":len(attacks),"expected_denials":sum(not x["expected_allow"] for x in attacks),"expected_denials_blocked":sum(x["status"]=="PASS" and not x["expected_allow"] and x["canary_blocked"] for x in attacks),"policy_permitted_canary_creations":sum(x["status"]=="PASS" and x["expected_allow"] and x["canary_created"] for x in attacks),"attack_controls_incomplete":sum(x["status"]!="PASS" for x in attacks),"exact_repeat_count":len(repeats),"exact_repeat_utility_passes":sum(x["utility_pass"] for x in repeats),"exact_repeat_security_passes":sum(x["security"]["status"]=="PASS" for x in repeats),"exact_repeat_contract_matches":sum(x["execution_identity_matches"] for x in repeats),"task_verifier_seconds":sum(v.get("task_process_seconds",0)+v.get("verifier_process_seconds",0) for v in values),"attributed_cli_wall_seconds":sum(v.get("wall_seconds_attributed",0) for v in values),"failures_or_inconclusive":len(values)-sum(v.get("utility_pass",False) for v in values)}
    drift=rows[0].get("contract_drift",{}) if rows else {}
    result["contract_drift"]={"cases":len(drift.get("cases",[])),"rejected_before_replay":sum(c["rejected_before_replay"] for c in drift.get("cases",[])),"all_rejected_before_replay":drift.get("all_rejected_before_replay",False)}
    result["exact_repeat_wall_seconds"]={}
    for label in ("B","F"):
        vals=[x for r in rows for x in r["exact_contract_repeats"].get(label,[])]
        result["exact_repeat_wall_seconds"][label]={"median_cli":statistics.median([x["cli_wall_seconds"] for x in vals]) if vals else None,"median_agent":statistics.median([x["agent_seconds"] for x in vals]) if vals else None,"median_verifier":statistics.median([x["verifier_seconds"] for x in vals]) if vals else None}
    result["total_wall_seconds"]=elapsed
    f_promoted=[r for r in rows if r["optimizers"]["F"].get("status")=="validated"]
    policy_points=[]
    incremental_tune=[]
    static_wall=[]
    for row in f_promoted:
        ceiling=row["baseline_cost"]["weighted_writable_exposure"]
        fcost=row["optimizers"]["F"]["cost"]["weighted_writable_exposure"]
        bcost=row["baselines"]["B"]["cost"]["weighted_writable_exposure"]
        if ceiling:
            policy_points.append(((ceiling-fcost)/ceiling-(ceiling-bcost)/ceiling)*100.0)
        incremental_tune.append(max(0.0,row["optimizers"]["F"]["wall_seconds_attributed"]-row["baseline_A"]["wall_seconds_attributed"]))
        static_wall.append(row["baselines"]["B"]["wall_seconds_attributed"])
    f_attack=result["methods"]["F"]; b_attack=result["methods"]["B"]
    f_rate=f_attack["expected_denials_blocked"]/len(rows) if rows else 0
    b_rate=b_attack["expected_denials_blocked"]/len(rows) if rows else 0
    median_tune=statistics.median(incremental_tune) if incremental_tune else None
    median_b=statistics.median(static_wall) if static_wall else None
    result["predeclared_decision_metrics"]={"f_promoted_tasks":len(f_promoted),"f_promotions_improving_weighted_surface_over_B_by_20pp":sum(x>=20 for x in policy_points),"median_F_minus_B_reduction_percentage_points":statistics.median(policy_points) if policy_points else None,"F_block_rate_over_all_canary_attempts":f_rate,"B_block_rate_over_all_canary_attempts":b_rate,"F_minus_B_block_rate_percentage_points":(f_rate-b_rate)*100,"median_incremental_F_tuning_wall_seconds":median_tune,"median_B_single_run_wall_seconds":median_b,"median_incremental_F_tuning_cost_per_protected_run_at_10_repetitions":median_tune/10 if median_tune is not None else None,"amortized_cost_gate_pass":bool(median_tune is not None and median_b is not None and median_tune/10<=median_b),"contract_drift_cases":result["contract_drift"]["cases"],"contract_drift_rejected_before_replay":result["contract_drift"]["rejected_before_replay"],"exact_repeat_F_all_pass":f_attack["exact_repeat_utility_passes"]==f_attack["exact_repeat_count"] and f_attack["exact_repeat_security_passes"]==f_attack["exact_repeat_count"],"mandatory_canary_controls_pass":all(all(x["status"]=="PASS" for x in r["unauthorized_write_attempts"].values()) for r in rows)}
    result["predeclared_decision_metrics"]["amortized_F_tuning_wall_seconds_by_future_repeat_count"]={str(n):median_tune/n if median_tune is not None else None for n in (1,3,10,50)}
    return result

if __name__=="__main__": raise SystemExit(main())
