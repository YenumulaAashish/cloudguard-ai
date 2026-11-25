"""Owner-reviewed AWS price export. No fixture prices or absent meters become zero."""
from decimal import Decimal,ROUND_CEILING
from cloudguard.phase6.config import require,digest

METERS={'t3.micro_hour','t3.small_hour','ebs_gp3_gb_month','ec2_monitoring_month','kms_key_month','kms_request','s3_source_gb_month','s3_replica_gb_month','s3_request','replication_request','replication_gb','internet_gb','flow_delivery_gb','audit_gb_month','state_month'}
UNITS={k:('instance-hour' if k.endswith('_hour') else 'key-month' if k=='kms_key_month' else 'GB-month' if k.endswith('_gb_month') else 'month' if k.endswith('_month') else 'request' if k.endswith('_request') else 'GB') for k in METERS}
def estimate(c,book,settings,now):
    try:
        require(set(book)=={'kind','currency','regions','as_of','expires_at','rates'},'PRICE_PROVENANCE_REQUIRED')
        require(book['kind']=='AWS_REVIEWED_EXPORT' and book['currency']=='USD' and book['regions']==['ap-south-1','ap-south-2'],'PRICE_PROVENANCE_REQUIRED')
        require(digest(book)==settings['price_digest'],'PRICE_BINDING_INVALID')
        require(type(book['as_of']) in (int,float) and type(book['expires_at']) in (int,float) and 0<book['expires_at']-book['as_of']<=604800 and book['as_of']<=now<book['expires_at'],'PRICE_STALE')
        require(set(book['rates'])==METERS,'PRICE_METERS_MISSING')
        p={}
        for k,v in book['rates'].items():
            require(set(v)=={'usd_per_unit','source','unit','sku','reviewed'},'PRICE_PROVENANCE_REQUIRED')
            require(v['reviewed'] is True and v['source'].startswith('https://aws.amazon.com/') and type(v['sku']) is str and 0<len(v['sku'])<=128 and v['unit']==UNITS[k],'PRICE_PROVENANCE_REQUIRED')
            require(type(v['usd_per_unit']) is str,'PRICE_INVALID');p[k]=Decimal(v['usd_per_unit']);require(p[k].is_finite() and p[k]>=0,'PRICE_INVALID')
        # Monthly ceiling, even if operator enters fewer compute hours. No automatic shutdown promise.
        # Three CMKs include remote state. Support stays billable after workload deletion.
        total=p['kms_key_month']*3+p['state_month']+p['audit_gb_month']*10
        if c['vpc']['enabled']:total+=p['flow_delivery_gb']*10
        if c['ec2']['enabled']:total+=p[c['ec2']['instance_type']+'_hour']*730+p['ebs_gp3_gb_month']*c['ec2']['root_gb']+p['ec2_monitoring_month']
        if c['s3']['enabled']:
            total+=(p['s3_source_gb_month']+p['s3_replica_gb_month'])*c['s3']['storage_gb']
            total+=(p['s3_request']+p['replication_request']+p['kms_request']*2)*c['s3']['requests']
            total+=p['replication_gb']*max(c['s3']['storage_gb'],c['s3']['transfer_gb'])+p['internet_gb']*c['s3']['transfer_gb']
        total=total.quantize(Decimal('.01'),rounding=ROUND_CEILING);limit=min(Decimal(c['budget_usd']),Decimal(settings['budget_usd']))
        return {'status':'PASS' if total<=limit else 'FAIL','estimate_usd':str(total),'limit_usd':str(limit),'mode':'LIVE_VERIFIED','reason':'WITHIN_LIVE_BUDGET' if total<=limit else 'BUDGET_EXCEEDED'}
    except Exception:return {'status':'UNKNOWN','estimate_usd':None,'limit_usd':settings['budget_usd'],'mode':'LIVE_UNVERIFIED','reason':'COST_UNKNOWN_OR_STALE'}
