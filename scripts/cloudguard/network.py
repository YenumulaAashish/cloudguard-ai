"""Offline rule-level network exposure; no runtime reachability inference."""
import ipaddress
from .plan_input import project, MAX_BYTES
from .iam import unknown
from .findings import serialize, finding, SEVERITIES, STATUSES
from .risk import read_document
from .runtime import ROOT

GROUPS = {"aws_security_group", "aws_default_security_group"}
RULES = {"aws_security_group_rule", "aws_vpc_security_group_ingress_rule", "aws_vpc_security_group_egress_rule"}
CONTEXT = {"aws_instance", "aws_lb", "aws_alb", "aws_db_instance", "aws_rds_cluster",
           "aws_elasticache_cluster", "aws_elasticache_replication_group", "aws_network_interface"}
DATABASE = {1433,1521,3306,5432,6379,27017}
MANAGEMENT = {23,5900,5985,5986}
CONTROLS = {
 "CGA_NET_001": ("CRITICAL", "Ingress allows all protocols from all addresses in the indicated family"),
 "CGA_NET_002": ("HIGH", "Ingress includes TCP port 22 from all addresses in the indicated family"),
 "CGA_NET_003": ("HIGH", "Ingress includes TCP port 3389 from all addresses in the indicated family"),
 "CGA_NET_004": ("HIGH", "Ingress includes the indicated common database TCP port from all addresses"),
 "CGA_NET_005": ("MEDIUM", "Ingress includes the indicated management TCP port from all addresses"),
 "CGA_NET_006": ("HIGH", "Ingress allows a public TCP/UDP range of at least 1024 ports"),
 "CGA_NET_007": ("LOW", "Ingress allows public ICMP; TCP service exposure is not inferred"),
 "CGA_NET_008": ("LOW", "Egress allows all protocols to all addresses in the indicated family"),
 "CGA_NET_009": ("UNKNOWN", "Unsupported or unresolved network context requires review")}
FIELDS = {"protocol", "ip_protocol", "from_port", "to_port", "cidr_blocks", "ipv6_cidr_blocks",
          "cidr_ipv4", "cidr_ipv6", "security_groups", "source_security_group_id",
          "referenced_security_group_id", "security_group_id", "self", "prefix_list_ids", "prefix_list_id", "type"}


def require(test):
    if not test: raise ValueError("Unsupported, malformed or oversized network input")


def values(value):
    if value is None: return []
    result = [value] if isinstance(value,str) else value
    require(isinstance(result,list) and len(result)<=128)
    require(all(isinstance(x,str) and 0<len(x)<=2048 for x in result))
    return result


def summary(rows):
    return {"total":len(rows),**{s.lower():sum(r["severity"]==s for r in rows) for s in SEVERITIES}}


def validate(report):
    from jsonschema import Draft202012Validator
    from referencing import Registry
    from referencing.exceptions import NoSuchResource
    def deny(uri): raise NoSuchResource(ref=uri)
    schema=read_document(ROOT/"security/network-report.schema.json")
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema,registry=Registry(retrieve=deny)).validate(report)
    require(report["summary"]==summary(report["findings"]))
    for r in report["findings"]:
        severity,message=CONTROLS[r["control_id"]]
        require((r["severity"],r["message"])==(severity,message))
        require(r["status"]==("UNKNOWN" if severity=="UNKNOWN" else "FINDING"))


def analyze(plan):
    indexed,changes=project(plan)
    rows=[]; rule_count=0
    def emit(address,direction,index,control,family="UNKNOWN",protocol="UNKNOWN",lo=None,hi=None,port=None):
        severity,message=CONTROLS[control]
        rows.append({"resource":address,"direction":direction,"rule_index":index,"control_id":control,
          "address_family":family,"protocol":protocol,"from_port":lo,"to_port":hi,"service_port":port,
          "severity":severity,"status":"UNKNOWN" if severity=="UNKNOWN" else "FINDING",
          "requires_review":True,"message":message})
        require(len(rows)<=20000)
    def inspect(address,direction,index,rule,mask):
        nonlocal rule_count
        rule_count+=1; require(rule_count<=4096)
        require(isinstance(rule,dict))
        require(rule.get("description") is None or (isinstance(rule["description"],str) and len(rule["description"])<=2048))
        if mask is True or (isinstance(mask,dict) and any(unknown(v) for k,v in mask.items() if k in FIELDS)):
            emit(address,direction,index,"CGA_NET_009"); return
        require(mask is None or isinstance(mask,(dict,bool)))
        raw=rule.get("ip_protocol",rule.get("protocol"))
        if raw is None: emit(address,direction,index,"CGA_NET_009"); return
        require(type(raw) in (str,int))
        protocol={"6":"tcp","17":"udp","1":"icmp","58":"icmpv6","-1":"all"}.get(str(raw).lower(),str(raw).lower())
        if protocol not in ("tcp","udp","icmp","icmpv6","all"):
            emit(address,direction,index,"CGA_NET_009"); return
        lo,hi=rule.get("from_port"),rule.get("to_port")
        if protocol in ("tcp","udp"):
            if lo is None or hi is None: emit(address,direction,index,"CGA_NET_009"); return
            require(type(lo) is int and type(hi) is int and 0<=lo<=hi<=65535)
        elif protocol in ("icmp","icmpv6"):
            if lo is None or hi is None: emit(address,direction,index,"CGA_NET_009"); return
            require(type(lo) is int and type(hi) is int and -1<=lo<=255 and -1<=hi<=255)
            require(lo!=-1 or hi==-1)
        else:
            lo=hi=None  # AWS all-protocol semantics ignore the port fields.
        families=set()
        for plural,singular,version in (("cidr_blocks","cidr_ipv4",4),("ipv6_cidr_blocks","cidr_ipv6",6)):
            for cidr in values(rule.get(plural))+values(rule.get(singular)):
                require('/' in cidr)
                try: net=ipaddress.ip_network(cidr,strict=True)
                except ValueError: raise ValueError("Malformed network CIDR") from None
                require(net.version==version)
                if net.prefixlen==0: families.add("IPv4" if version==4 else "IPv6")
        refs=[]
        for key in ("security_groups","source_security_group_id","referenced_security_group_id"):
            refs+=values(rule.get(key))
        self_ref=rule.get("self",False); require(type(self_ref) is bool)
        prefixes=values(rule.get("prefix_list_ids"))+values(rule.get("prefix_list_id"))
        has_cidr=any(rule.get(k) for k in ("cidr_blocks","ipv6_cidr_blocks","cidr_ipv4","cidr_ipv6"))
        if prefixes or not (has_cidr or refs or self_ref): emit(address,direction,index,"CGA_NET_009")
        for family in sorted(families):
            if direction=="egress":
                if protocol=="all": emit(address,direction,index,"CGA_NET_008",family,protocol)
                continue
            if protocol=="all": emit(address,direction,index,"CGA_NET_001",family,protocol); continue
            if protocol in ("icmp","icmpv6"):
                if (protocol=="icmp" and family=="IPv6") or (protocol=="icmpv6" and family=="IPv4"):
                    emit(address,direction,index,"CGA_NET_009",family,protocol)
                else: emit(address,direction,index,"CGA_NET_007",family,protocol,lo,hi)
                continue
            if hi-lo+1>=1024:
                emit(address,direction,index,"CGA_NET_006",family,protocol,lo,hi); continue
            if protocol=="tcp":
                for port,control in [(22,"CGA_NET_002"),(3389,"CGA_NET_003")]+[(p,"CGA_NET_004") for p in sorted(DATABASE)]+[(p,"CGA_NET_005") for p in sorted(MANAGEMENT)]:
                    if lo<=port<=hi: emit(address,direction,index,control,family,protocol,lo,hi,port)
    for address,row in sorted(indexed.items()):
        typ=row["type"]
        if typ not in GROUPS|RULES|CONTEXT and not typ.startswith("aws_security_group"): continue
        require(0<len(address)<=2048)
        change=changes.get(address,{}).get("change",{})
        if change.get("actions")==["delete"]: continue
        v=row.get("values"); mask=change.get("after_unknown",{})
        if typ in CONTEXT or typ not in GROUPS|RULES:
            emit(address,"UNKNOWN",None,"CGA_NET_009"); continue
        if v is None or mask is True:
            emit(address,"UNKNOWN",None,"CGA_NET_009"); continue
        require(isinstance(v,dict) and isinstance(mask,dict))
        if typ in GROUPS:
            for direction in ("ingress","egress"):
                part=mask.get(direction)
                if unknown(part):
                    emit(address,direction,None,"CGA_NET_009"); continue
                rules=v.get(direction)
                if rules is None:
                    emit(address,direction,None,"CGA_NET_009"); continue
                require(isinstance(rules,list) and len(rules)<=256)
                for index,rule in enumerate(rules): inspect(address,direction,index,rule,{})
        else:
            direction="ingress" if typ=="aws_vpc_security_group_ingress_rule" else "egress" if typ=="aws_vpc_security_group_egress_rule" else v.get("type")
            if direction not in ("ingress","egress"):
                emit(address,"UNKNOWN",0,"CGA_NET_009"); continue
            inspect(address,direction,0,v,mask)
    rows.sort(key=lambda r:(r["resource"],r["direction"],-1 if r["rule_index"] is None else r["rule_index"],r["address_family"],r["control_id"],r["service_port"] or -1))
    report={"schema_version":"1.0","analyzer":"cloudguard-network","analysis_scope":"rule_configuration_only","findings":rows,"summary":summary(rows)}
    validate(report); return report


def normalized(report):
    validate(report)
    rows=[finding("conftest",r["control_id"],r["resource"],"warning" if r["status"]=="UNKNOWN" else "failed",r["severity"],r["message"],metadata={"analyzer":"cloudguard-network",**{k:r[k] for k in ("direction","rule_index","address_family","protocol","service_port")}}) for r in report["findings"]]
    return {"schema_version":"1.0","generated_by":"cloudguard-ai","sources":["conftest"],"findings":rows,
            "summary":{"total":len(rows),**{s.lower():sum(r["severity"]==s for r in rows) for s in SEVERITIES},**{s:sum(r["status"]==s for r in rows) for s in STATUSES}}}
