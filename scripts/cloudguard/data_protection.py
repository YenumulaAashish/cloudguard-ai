"""Deterministic local S3 configuration posture; never AWS runtime claims."""
import json
from .plan_input import project, MAX_BYTES
from .iam import unknown
from .findings import finding, serialize, SEVERITIES, STATUSES
from .risk import read_document
from .runtime import ROOT

KINDS={"public_access_block":"pab", "acl":"acl", "policy":"policy",
       "server_side_encryption_configuration":"encryption", "versioning":"versioning",
       "logging":"logging", "lifecycle_configuration":"lifecycle"}
CATEGORIES=("pab","acl","policy","transport","encryption","versioning","logging","lifecycle")
CONTROLS={
 "CGA_DATA_001":("HIGH","Public-access-block protections explicitly include disabled settings"),
 "CGA_DATA_002":("MEDIUM","Complete public-access-block configuration is missing from the supported plan"),
 "CGA_DATA_003":("MEDIUM","ACL configuration explicitly permits public reads; effective access requires review"),
 "CGA_DATA_004":("CRITICAL","ACL configuration explicitly permits public reads and writes; effective access requires review"),
 "CGA_DATA_005":("HIGH","Bucket policy structurally allows a public principal supported S3 actions on this bucket"),
 "CGA_DATA_006":("MEDIUM","Supported explicit server-side encryption configuration is not established"),
 "CGA_DATA_007":("MEDIUM","Enabled versioning configuration is not established"),
 "CGA_DATA_008":("LOW","S3 access logging is not configured in the supported plan"),
 "CGA_DATA_009":("MEDIUM","Bucket policy does not establish the recognized SecureTransport Deny pattern"),
 "CGA_DATA_010":("LOW","A global enabled multipart-upload abort rule within seven days is not established"),
 "CGA_DATA_011":("UNKNOWN","Unsupported or unresolved S3 configuration requires review")}
PAB=("block_public_acls","ignore_public_acls","block_public_policy","restrict_public_buckets")
S3_ACTIONS={"s3:*","*","s3:getobject","s3:putobject","s3:deleteobject","s3:listbucket","s3:getobjectversion"}


def require(test):
    if not test: raise ValueError("Unsupported, malformed or oversized S3 input")


def strings(value):
    result=[value] if isinstance(value,str) else value
    require(isinstance(result,list) and 0<len(result)<=128)
    require(all(isinstance(x,str) and 0<len(x)<=2048 for x in result))
    return result


def single(value):
    require(isinstance(value,list) and len(value)==1 and isinstance(value[0],dict))
    return value[0]


def summary(rows):
    return {"total":len(rows),**{s.lower():sum(r["severity"]==s for r in rows) for s in SEVERITIES}}


def validate(report):
    from jsonschema import Draft202012Validator
    from referencing import Registry
    from referencing.exceptions import NoSuchResource
    def deny(uri): raise NoSuchResource(ref=uri)
    schema=read_document(ROOT/"security/data-protection-report.schema.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema,registry=Registry(retrieve=deny)).validate(report)
    require(report["summary"]==summary(report["findings"]))
    for row in report["findings"]:
        severity,message=CONTROLS[row["control_id"]]
        require((row["severity"],row["message"])==(severity,message))
        require(row["status"]==("UNKNOWN" if severity=="UNKNOWN" else "FINDING"))


def analyze(plan):
    indexed,changes=project(plan)
    active={a:r for a,r in indexed.items() if changes.get(a,{}).get("change",{}).get("actions")!=["delete"]}
    buckets={a:r for a,r in active.items() if r["type"]=="aws_s3_bucket"}
    require(len(buckets)<=256)
    rows=[];checks=[];maps={a:{} for a in buckets};unresolved=set()
    def emit(address,category,control):
        severity,message=CONTROLS[control]
        row={"resource":address,"category":category,"control_id":control,"severity":severity,
             "status":"UNKNOWN" if severity=="UNKNOWN" else "FINDING","requires_review":True,"message":message}
        if row not in rows: rows.append(row)
        require(len(rows)<=8192)
    def check(a,c,state,control=None,mode="NONE"):
        checks.append({"resource":a,"category":c,"state":state,"encryption_mode":mode})
        if control: emit(a,c,control)
    def mask(a): return changes.get(a,{}).get("change",{}).get("after_unknown",{})
    def uncertain(a,fields=None):
        m=mask(a)
        if m is True:return True
        require(isinstance(m,dict))
        return any(unknown(v) for k,v in m.items() if fields is None or k in fields)
    names={};identities={}
    for a,r in buckets.items():
        require(0<len(a)<=2048)
        v=r.get("values");require(v is None or isinstance(v,dict))
        identity=set()
        for field in ("bucket","id"):
            value=(v or {}).get(field)
            if value is not None:
                require(isinstance(value,str) and 0<len(value)<=2048)
                if not uncertain(a,{field}):identity.add(value)
        identities[a]=identity
        for value in identity:
            require(value not in names or names[value]==a);names[value]=a
    for a,r in sorted(active.items()):
        typ=r["type"]
        if not typ.startswith("aws_s3_") or typ=="aws_s3_bucket":continue
        require(0<len(a)<=2048)
        kind=KINDS.get(typ.removeprefix("aws_s3_bucket_"))
        if not typ.startswith("aws_s3_bucket_") or kind is None:
            emit(a,"context","CGA_DATA_011");continue
        v=r.get("values");require(v is None or isinstance(v,dict))
        target=(v or {}).get("bucket")
        if target is not None: require(isinstance(target,str) and 0<len(target)<=2048)
        if uncertain(a,{"bucket"}) or target not in names:
            unresolved.add(kind);emit(a,kind,"CGA_DATA_011");continue
        owner=names[target];require(kind not in maps[owner]);maps[owner][kind]=(a,v)
    def body_policy(a,raw,arn):
        if isinstance(raw,str):
            require(len(raw.encode())<=262144)
            def unique(pairs):
                obj={}
                for k,v in pairs:require(k not in obj);obj[k]=v
                return obj
            raw=json.loads(raw,object_pairs_hook=unique)
        require(isinstance(raw,dict) and len(serialize(raw).encode())<=262144)
        statements=raw.get("Statement")
        if isinstance(statements,dict):statements=[statements]
        if statements is None:return False,True,False
        require(isinstance(statements,list) and len(statements)<=256)
        public=False;review=False;tls=False
        for s in statements:
            require(isinstance(s,dict))
            if any(k in s for k in ("NotPrincipal","NotAction","NotResource")):
                review=True;continue
            if s.get("Effect") not in ("Allow","Deny"):
                review=True;continue
            if any(s.get(k) is None for k in ("Principal","Action","Resource")):
                review=True;continue
            principal=s["Principal"]
            is_public=principal=="*"
            if isinstance(principal,dict) and "AWS" in principal:
                is_public="*" in strings(principal["AWS"])
            if isinstance(principal,dict):
                require(len(principal)<=8)
                for value in principal.values():strings(value)
                if set(principal)-{"AWS"}:review=True
            else:strings(principal)
            actions=[x.lower() for x in strings(s["Action"])];resources=strings(s["Resource"])
            condition=s.get("Condition",{});require(isinstance(condition,dict) and len(condition)<=32)
            for terms in condition.values():
                require(isinstance(terms,dict) and len(terms)<=128)
                for key,value in terms.items():
                    require(isinstance(key,str) and len(key)<=2048)
                    if isinstance(value,list):
                        require(len(value)<=128)
                        require(all(type(x) in (str,bool,int) for x in value))
                    else:require(type(value) in (str,bool,int))
                    for item in (value if isinstance(value,list) else [value]):
                        require(not isinstance(item,str) or len(item)<=2048)
            target=bool(arn and any(x in resources for x in (arn,arn+"/*"))) or "*" in resources
            covers_all="*" in resources or bool(arn and arn in resources and arn+"/*" in resources)
            if s["Effect"]=="Deny":
                expected=condition.get("Bool",{}).get("aws:SecureTransport")
                if (is_public and any(x in actions for x in ("*","s3:*")) and covers_all
                    and set(condition)=={"Bool"} and set(condition["Bool"])=={"aws:SecureTransport"}
                    and (expected is False or expected=="false")):
                    tls=True
                continue
            if not is_public:continue
            if condition:review=True;continue
            if not target:review=True;continue
            if not all(x in S3_ACTIONS for x in actions):review=True;continue
            object_actions={"s3:getobject","s3:putobject","s3:deleteobject","s3:getobjectversion"}
            meaningful=any((x in ("*","s3:*") and target) or
                          (x in object_actions and ("*" in resources or bool(arn and arn+"/*" in resources))) or
                          (x=="s3:listbucket" and ("*" in resources or bool(arn and arn in resources))) for x in actions)
            if meaningful:public=True
            else:review=True
        return public,review,tls
    for a,r in sorted(buckets.items()):
        v=r.get("values") or {}
        arn=v.get("arn") if not uncertain(a,{"arn"}) else None
        require(arn is None or (isinstance(arn,str) and len(arn)<=2048))
        # Inline legacy fields are explicitly unsupported, not silently combined.
        legacy={"acl","policy","versioning","logging","lifecycle_rule","server_side_encryption_configuration"}
        for c in CATEGORIES:
            kind="policy" if c=="transport" else c
            entry=maps[a].get(kind)
            if not identities[a] or kind in unresolved or uncertain(a,legacy) or any(v.get(k) for k in legacy):
                check(a,c,"UNKNOWN","CGA_DATA_011");continue
            if entry is None:
                missing={"pab":"CGA_DATA_002","encryption":"CGA_DATA_006","versioning":"CGA_DATA_007","logging":"CGA_DATA_008","transport":"CGA_DATA_009","lifecycle":"CGA_DATA_010"}
                check(a,c,"MISSING",missing.get(c));continue
            ca,cv=entry
            fields={"pab":set(PAB),"acl":{"acl","access_control_policy"},"policy":{"policy"},"transport":{"policy"},"encryption":{"rule"},"versioning":{"versioning_configuration"},"logging":{"target_bucket"},"lifecycle":{"rule"}}[c]
            if cv is None or uncertain(ca,fields):
                check(a,c,"UNKNOWN","CGA_DATA_011");continue
            if c=="pab":
                vals=[cv.get(k) for k in PAB]
                require(all(x is None or type(x) is bool for x in vals))
                if any(x is False for x in vals):check(a,c,"WEAK","CGA_DATA_001")
                elif any(x is None for x in vals):check(a,c,"UNKNOWN","CGA_DATA_011")
                else:check(a,c,"ESTABLISHED")
            elif c=="acl":
                acl=cv.get("acl")
                if cv.get("access_control_policy"):
                    check(a,c,"UNKNOWN","CGA_DATA_011")
                elif acl=="public-read-write":check(a,c,"WEAK","CGA_DATA_004")
                elif acl=="public-read":check(a,c,"WEAK","CGA_DATA_003")
                elif acl in ("private","bucket-owner-read","bucket-owner-full-control","log-delivery-write"):check(a,c,"REVIEWED")
                else:check(a,c,"UNKNOWN","CGA_DATA_011")
            elif c in ("policy","transport"):
                if cv.get("policy") is None:check(a,c,"UNKNOWN","CGA_DATA_011");continue
                public,review,tls=body_policy(a,cv["policy"],arn)
                if c=="policy":
                    if public:emit(a,c,"CGA_DATA_005")
                    check(a,c,"UNKNOWN" if review else "WEAK" if public else "REVIEWED","CGA_DATA_011" if review else None)
                elif tls:check(a,c,"ESTABLISHED")
                elif review:check(a,c,"UNKNOWN","CGA_DATA_011")
                else:check(a,c,"WEAK","CGA_DATA_009")
            elif c=="encryption":
                if cv.get("rule") is None:check(a,c,"UNKNOWN","CGA_DATA_011");continue
                rule=single(cv["rule"])
                enc=single(rule.get("apply_server_side_encryption_by_default"))
                algorithm=enc.get("sse_algorithm")
                if algorithm in ("AES256","aws:kms"):
                    check(a,c,"ESTABLISHED",mode=algorithm)
                else:check(a,c,"UNKNOWN","CGA_DATA_011",mode="UNKNOWN")
            elif c=="versioning":
                if cv.get("versioning_configuration") is None:check(a,c,"UNKNOWN","CGA_DATA_011");continue
                status=single(cv["versioning_configuration"]).get("status")
                if status=="Enabled":check(a,c,"ESTABLISHED")
                elif status in ("Suspended","Disabled"):check(a,c,"WEAK","CGA_DATA_007")
                else:check(a,c,"UNKNOWN","CGA_DATA_011")
            elif c=="logging":
                target=cv.get("target_bucket")
                if target is None:check(a,c,"UNKNOWN","CGA_DATA_011")
                else:
                    require(isinstance(target,str) and len(target)<=2048)
                    check(a,c,"ESTABLISHED" if target else "WEAK",None if target else "CGA_DATA_008")
            elif c=="lifecycle":
                rules=cv.get("rule")
                if rules is None:check(a,c,"UNKNOWN","CGA_DATA_011");continue
                require(isinstance(rules,list) and len(rules)<=256)
                good=False;review=False
                for rule in rules:
                    require(isinstance(rule,dict))
                    if rule.get("status") not in ("Enabled","Disabled"):review=True;continue
                    if rule["status"]=="Disabled":continue
                    abort=rule.get("abort_incomplete_multipart_upload",[])
                    if not abort:continue
                    days=single(abort).get("days_after_initiation")
                    if days is None:review=True;continue
                    require(type(days) is int and days>0)
                    filters=rule.get("filter",[])
                    require(isinstance(filters,list) and len(filters)<=1)
                    empty_filter=not filters or (isinstance(filters[0],dict) and
                        set(filters[0])<={"prefix","tag","and","object_size_greater_than","object_size_less_than"} and
                        all(value in (None,"",[],{}) for value in filters[0].values()))
                    global_rule=empty_filter and rule.get("prefix") in (None,"")
                    if global_rule and days<=7:good=True
                check(a,c,"ESTABLISHED" if good else "UNKNOWN" if review else "WEAK",None if good else "CGA_DATA_011" if review else "CGA_DATA_010")
    rows.sort(key=lambda x:(x["resource"],x["category"],x["control_id"]))
    checks.sort(key=lambda x:(x["resource"],x["category"]))
    report={"schema_version":"1.0","analyzer":"cloudguard-data","scope":"s3","analysis_scope":"configuration_only","findings":rows,"checks":checks,"summary":summary(rows)}
    validate(report);return report


def normalized(report):
    validate(report)
    rows=[finding("conftest",r["control_id"],r["resource"],"warning" if r["status"]=="UNKNOWN" else "failed",r["severity"],r["message"],metadata={"analyzer":"cloudguard-data","scope":"s3","category":r["category"]}) for r in report["findings"]]
    return {"schema_version":"1.0","generated_by":"cloudguard-ai","sources":["conftest"],"findings":rows,"summary":{"total":len(rows),**{s.lower():sum(r["severity"]==s for r in rows) for s in SEVERITIES},**{s:sum(r["status"]==s for r in rows) for s in STATUSES}}}
