"""Closed configuration and deterministic templates. No arbitrary HCL or identities."""
from copy import deepcopy
import hashlib
import ipaddress
import json
import re

TEMPLATE_VERSION='phase6-mock-1'
REGION='ap-south-1'

def require(ok,code='INVALID_CONFIGURATION'):
    if not ok:raise ValueError(code)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False)
def digest(value):return hashlib.sha256(canonical(value).encode()).hexdigest()
def keys(value,names):require(type(value) is dict and set(value)==set(names))
def integer(value,lo,hi):require(type(value) is int and lo<=value<=hi)

def validate(c):
    keys(c,('project','region','vpc','ec2','s3','budget_usd'))
    require(type(c['project']) is str and re.fullmatch('[a-z][a-z0-9-]{2,23}',c['project']))
    require(c['region']==REGION)
    keys(c['vpc'],('enabled','cidr','subnet_cidr'))
    keys(c['ec2'],('enabled','instance_type','ami','root_gb','hours'))
    keys(c['s3'],('enabled','storage_gb','requests','transfer_gb'))
    for name in ('vpc','ec2','s3'):require(type(c[name]['enabled']) is bool)
    private=[ipaddress.ip_network(n) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')]
    net=ipaddress.ip_network(c['vpc']['cidr'],strict=True);sub=ipaddress.ip_network(c['vpc']['subnet_cidr'],strict=True)
    require(net.version==sub.version==4 and 16<=net.prefixlen<=24 and 24<=sub.prefixlen<=28)
    require(any(net.subnet_of(n) for n in private) and sub.subnet_of(net))
    require(c['ec2']['instance_type'] in ('t3.micro','t3.small') and c['ec2']['ami']=='mock-al2023')
    require(not c['ec2']['enabled'] or c['vpc']['enabled'])
    integer(c['ec2']['root_gb'],8,30);integer(c['ec2']['hours'],1,730)
    integer(c['s3']['storage_gb'],0,100);integer(c['s3']['requests'],0,100000);integer(c['s3']['transfer_gb'],0,10)
    require(type(c['budget_usd']) is str and re.fullmatch(r'(?:0|[1-9][0-9]{0,3})\.[0-9]{2}',c['budget_usd']))
    require(float(c['budget_usd'])>0)
    return deepcopy(c)

def generate(config):
    c=validate(config);resources={};tags={'Project':c['project'],'Environment':'sandbox','ManagedBy':'Terraform'}
    def add(kind,values):resources[kind+'.this']={'type':kind,'values':values}
    if c['vpc']['enabled']:
        add('aws_vpc',{'cidr_block':c['vpc']['cidr'],'enable_dns_support':True,'enable_dns_hostnames':True,'tags':tags})
        add('aws_subnet',{'vpc_id':'${aws_vpc.this.id}','cidr_block':c['vpc']['subnet_cidr'],'availability_zone':REGION+'a','map_public_ip_on_launch':False,'tags':tags})
        add('aws_security_group',{'name_prefix':'cg-mock-','description':'Private mock workload boundary','vpc_id':'${aws_vpc.this.id}','ingress':[],'egress':[],'tags':tags})
        add('aws_default_security_group',{'vpc_id':'${aws_vpc.this.id}','ingress':[],'egress':[],'tags':tags})
        add('aws_route_table',{'vpc_id':'${aws_vpc.this.id}','tags':tags})
        add('aws_route_table_association',{'subnet_id':'${aws_subnet.this.id}','route_table_id':'${aws_route_table.this.id}'})
    if c['ec2']['enabled']:
        add('aws_instance',{'ami':'ami-00000000000000000','instance_type':c['ec2']['instance_type'],'subnet_id':'${aws_subnet.this.id}',
          'vpc_security_group_ids':['${aws_security_group.this.id}'],'associate_public_ip_address':False,'monitoring':True,'ebs_optimized':True,
          'metadata_options':[{'http_endpoint':'enabled','http_tokens':'required','http_put_response_hop_limit':1}],
          'root_block_device':[{'encrypted':True,'volume_type':'gp3','volume_size':c['ec2']['root_gb']}],'tags':tags})
    if c['s3']['enabled']:
        bucket='cg-mock-'+c['project']+'-'+digest(c['project'])[:8]
        add('aws_s3_bucket',{'bucket':bucket,'force_destroy':False,'tags':tags})
        add('aws_s3_bucket_public_access_block',dict(bucket=bucket,block_public_acls=True,block_public_policy=True,ignore_public_acls=True,restrict_public_buckets=True))
        add('aws_s3_bucket_server_side_encryption_configuration',{'bucket':bucket,'rule':[{'apply_server_side_encryption_by_default':[{'sse_algorithm':'AES256'}]}]})
        add('aws_s3_bucket_versioning',{'bucket':bucket,'versioning_configuration':[{'status':'Enabled'}]})
        add('aws_s3_bucket_ownership_controls',{'bucket':bucket,'rule':[{'object_ownership':'BucketOwnerEnforced'}]})
        add('aws_s3_bucket_lifecycle_configuration',{'bucket':bucket,'rule':[{'id':'abort-incomplete','status':'Enabled','filter':[{}],'abort_incomplete_multipart_upload':[{'days_after_initiation':7}]}]})
        policy={'Version':'2012-10-17','Statement':[{'Effect':'Deny','Principal':'*','Action':'s3:*','Resource':['${aws_s3_bucket.this.arn}','${aws_s3_bucket.this.arn}/*'],'Condition':{'Bool':{'aws:SecureTransport':'false'}}}]}
        add('aws_s3_bucket_policy',{'bucket':bucket,'policy':json.dumps(policy,sort_keys=True)})
    tf={'terraform':{'required_version':'= 1.9.8','required_providers':{'aws':{'source':'hashicorp/aws','version':'= 6.65.0'}}},'provider':{'aws':{'region':REGION}},'resource':{}}
    for address,r in resources.items():
        kind,label=address.split('.');tf['resource'].setdefault(kind,{})[label]=deepcopy(r['values'])
        if kind.startswith('aws_s3_bucket_'):tf['resource'][kind][label]['bucket']='${aws_s3_bucket.this.id}'
    return tf,resources

def mock_plan(resources,before):
    # Provider-shaped fixture only. Never label this a native Terraform/AWS plan.
    values=[];changes=[]
    for address in sorted(set(resources)|set(before)):
        after=resources.get(address);old=before.get(address)
        action='create' if old is None else 'delete' if after is None else 'no-op' if after==old else 'update'
        r=after or old
        if after:values.append({'address':address,'mode':'managed','type':r['type'],'name':'this','values':deepcopy(after['values'])})
        actions=[action]
        immutable={'aws_vpc':{'cidr_block'},'aws_subnet':{'vpc_id','cidr_block','availability_zone'},'aws_instance':{'ami','subnet_id'},'aws_s3_bucket':{'bucket'}}
        if action=='update' and any(old['values'].get(k)!=after['values'].get(k) for k in immutable.get(r['type'],set())):actions=['delete','create']
        changes.append({'address':address,'mode':'managed','type':r['type'],'name':'this','change':{'actions':actions,'before':old['values'] if old else None,'after':after['values'] if after else None,'after_unknown':{}}})
    return {'format_version':'1.2','terraform_version':'1.9.8','mock_only':True,'planned_values':{'root_module':{'resources':values}},'resource_changes':changes}


BLOCK_FIELDS={'metadata_options','root_block_device','versioning_configuration','rule','apply_server_side_encryption_by_default','filter','abort_incomplete_multipart_upload'}
def render_hcl(tf):
    """Render only the closed generated structure; never parse caller-supplied HCL."""
    def fields(values,depth):
        lines=[];pad='  '*depth
        for key,value in sorted(values.items()):
            if key in BLOCK_FIELDS:
                for block in value:lines += [pad+key+' {',*fields(block,depth+1),pad+'}']
            else:lines.append(pad+key+' = '+json.dumps(value,sort_keys=True))
        return lines
    lines=['terraform {','  required_version = "= 1.9.8"','  required_providers {','    aws = { source = "hashicorp/aws", version = "= 6.65.0" }','  }','}', 'provider "aws" {','  region = "ap-south-1"','}']
    for kind,labels in sorted(tf['resource'].items()):
        for label,values in sorted(labels.items()):lines += ['resource '+json.dumps(kind)+' '+json.dumps(label)+' {',*fields(values,1),'}']
    return '\n'.join(lines)+'\n'
