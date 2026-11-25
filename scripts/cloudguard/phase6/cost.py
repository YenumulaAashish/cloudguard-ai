"""Decimal mock estimates; no live AWS price lookup, missing prices never become zero."""
from decimal import Decimal,ROUND_CEILING
from datetime import datetime
from .config import require,digest

def estimate(c,catalog,cap,now):
    try:
        require(catalog['mode']=='MOCK_ONLY' and catalog['currency']=='USD','COST_UNKNOWN')
        stamp=lambda s:datetime.fromisoformat(s.replace('Z','+00:00')).timestamp()
        require(stamp(catalog['as_of'])<=now<stamp(catalog['expires_at']),'COST_STALE')
        p=catalog['unit_prices'];d=lambda k:Decimal(p[k])
        require(all(type(v) is str and Decimal(v).is_finite() and Decimal(v)>=0 for v in p.values()),'COST_UNKNOWN')
        total=d('support_monthly') if c['vpc']['enabled'] or c['s3']['enabled'] else Decimal('0')
        if c['vpc']['enabled']:total+=d('flow_log_gb')
        if c['s3']['enabled']:total+=d('replica_gb_month')*c['s3']['storage_gb']+d('replication_transfer_gb')*c['s3']['storage_gb']
        if c['ec2']['enabled']:total+=d(c['ec2']['instance_type'])*c['ec2']['hours']+d('ebs_gb_month')*c['ec2']['root_gb']+d('monitoring_month')
        if c['s3']['enabled']:total+=d('s3_gb_month')*c['s3']['storage_gb']+d('s3_request')*c['s3']['requests']+d('transfer_gb')*c['s3']['transfer_gb']
        total=total.quantize(Decimal('0.01'),rounding=ROUND_CEILING);limit=min(Decimal(c['budget_usd']),Decimal(cap))
        require(limit.is_finite() and limit>0,'BUDGET_INVALID')
        return {'status':'PASS' if total<=limit else 'FAIL','estimate_usd':str(total),'limit_usd':str(limit),'mode':'MOCK_ONLY',
            'reason':'WITHIN_MOCK_BUDGET' if total<=limit else 'BUDGET_EXCEEDED','catalog_digest':digest(catalog),'expires_at':catalog['expires_at']}
    except Exception:return {'status':'UNKNOWN','estimate_usd':None,'limit_usd':str(cap),'mode':'MOCK_ONLY','reason':'COST_UNKNOWN_OR_STALE'}
