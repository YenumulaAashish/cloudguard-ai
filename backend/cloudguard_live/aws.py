"""Explicit, lazy SDK access. No default credential chain and no API retries."""
import json
import os
import time
from cloudguard.phase6.config import require,digest

class AWS:
    def __init__(self,authority,factory=None):self.auth=authority;self.factory=factory;self.checked_at=0;self.binding=None;self.credential_binding=None
    def client(self,name,region='ap-south-1'):
        self.auth.check('read');creds=self.auth.credentials()
        if self.factory:return self.factory(name,region)
        import boto3
        from botocore.config import Config
        from botocore.session import Session
        core=Session()
        core.set_config_variable('config_file',os.devnull)
        core.set_config_variable('credentials_file',os.devnull)
        session=boto3.Session(botocore_session=core,aws_access_key_id=creds['AWS_ACCESS_KEY_ID'],aws_secret_access_key=creds['AWS_SECRET_ACCESS_KEY'],aws_session_token=creds['AWS_SESSION_TOKEN'],region_name=region)
        return session.client(name,config=Config(ignore_configured_endpoint_urls=True,retries={'total_max_attempts':1},connect_timeout=5,read_timeout=20,proxies={}))
    def bucket(self,name,region,encryption,key=None,versioned=True):
        s3=self.client('s3',region);args={'Bucket':name,'ExpectedBucketOwner':self.auth.c['account_id']}
        require((s3.get_bucket_location(**args)['LocationConstraint'] or 'us-east-1')==region,'SUPPORT_REGION_MISMATCH')
        if versioned:require(s3.get_bucket_versioning(**args).get('Status')=='Enabled','SUPPORT_VERSIONING_REQUIRED')
        p=s3.get_public_access_block(**args)['PublicAccessBlockConfiguration'];require(all(p.get(n) is True for n in ('BlockPublicAcls','BlockPublicPolicy','IgnorePublicAcls','RestrictPublicBuckets')),'PUBLIC_ACCESS_BLOCK_REQUIRED')
        rule=s3.get_bucket_encryption(**args)['ServerSideEncryptionConfiguration']['Rules'];require(len(rule)==1,'EXACT_ENCRYPTION_REQUIRED')
        default=rule[0]['ApplyServerSideEncryptionByDefault'];require(default['SSEAlgorithm']==encryption,'SUPPORT_ENCRYPTION_MISMATCH')
        if key:require(default.get('KMSMasterKeyID')==key,'SUPPORT_KMS_MISMATCH')
        require(s3.get_bucket_ownership_controls(**args)['OwnershipControls']['Rules']==[{'ObjectOwnership':'BucketOwnerEnforced'}],'ACL_DISABLED_REQUIRED')
        require(s3.get_bucket_policy_status(**args)['PolicyStatus']['IsPublic'] is False,'PRIVATE_BUCKET_REQUIRED')
        policy=json.loads(s3.get_bucket_policy(**args)['Policy'])
        tls=[s for s in policy.get('Statement',[]) if s.get('Effect')=='Deny' and s.get('Principal')=='*' and s.get('Action')=='s3:*' and s.get('Condition',{}).get('Bool',{}).get('aws:SecureTransport') in ('false',False)]
        require(any(set(s.get('Resource',[]))=={'arn:aws:s3:::'+name,'arn:aws:s3:::'+name+'/*'} for s in tls),'TLS_DENY_REQUIRED')
        return policy
    def verify(self):
        self.checked_at=0;self.binding=None;self.credential_binding=None;c=self.auth.c;s=c['support']
        a=self.auth.check('read');identity=self.client('sts').get_caller_identity()
        require(identity.get('Account')==c['account_id'] and identity.get('Arn','').startswith('arn:aws:sts::'+c['account_id']+':assumed-role/'+c['role_name']+'/'),'LIVE_IDENTITY_MISMATCH')
        self.bucket(c['state_bucket'],'ap-south-1','aws:kms',c['state_kms_key'])
        self.bucket(s['replica_bucket'],'ap-south-2','aws:kms',s['replica_kms_key'])
        audit=self.bucket(s['audit_bucket'],'ap-south-1','AES256',versioned=False)
        require(not self.client('s3').get_bucket_logging(Bucket=s['audit_bucket'],ExpectedBucketOwner=c['account_id']).get('LoggingEnabled'),'AUDIT_SELF_LOGGING_DENIED')
        for service in ('logging.s3.amazonaws.com','delivery.logs.amazonaws.com'):
            require(any(x.get('Effect')=='Allow' and x.get('Principal')=={'Service':service} and x.get('Condition',{}).get('StringEquals',{}).get('aws:SourceAccount')==c['account_id'] for x in audit.get('Statement',[])),'AUDIT_DELIVERY_POLICY_REQUIRED')
        for key,region in ((c['state_kms_key'],'ap-south-1'),(s['kms_key'],'ap-south-1'),(s['replica_kms_key'],'ap-south-2')):
            kms=self.client('kms',region);meta=kms.describe_key(KeyId=key)['KeyMetadata']
            require(meta['Arn']==key and meta['KeyManager']=='CUSTOMER' and meta['KeyState']=='Enabled' and kms.get_key_rotation_status(KeyId=key)['KeyRotationEnabled'] is True,'KMS_GUARD_REQUIRED')
        table=self.client('dynamodb').describe_table(TableName=c['lock_table'])['Table']
        require(table['TableStatus']=='ACTIVE' and table['KeySchema']==[{'AttributeName':'LockID','KeyType':'HASH'}] and {'AttributeName':'LockID','AttributeType':'S'} in table['AttributeDefinitions'],'STATE_LOCK_TABLE_INVALID')
        iam=self.client('iam');roles=iam.get_instance_profile(InstanceProfileName=s['instance_profile'])['InstanceProfile']['Roles']
        require(len(roles)==1 and roles[0]['RoleName']==s['instance_role'],'EXACT_INSTANCE_ROLE_REQUIRED')
        role=iam.get_role(RoleName=s['instance_role'])['Role']
        require(role.get('PermissionsBoundary',{}).get('PermissionsBoundaryArn')==s['boundary_arn'],'DENY_BOUNDARY_REQUIRED')
        boundary=iam.get_policy(PolicyArn=s['boundary_arn'])['Policy']
        document=iam.get_policy_version(PolicyArn=s['boundary_arn'],VersionId=boundary['DefaultVersionId'])['PolicyVersion']['Document']
        require(any(x.get('Effect')=='Deny' and x.get('Action')=='*' and x.get('Resource')=='*' and not x.get('Condition') for x in document.get('Statement',[])),'DENY_BOUNDARY_REQUIRED')
        require(iam.list_role_policies(RoleName=s['instance_role'])['PolicyNames']==[] and not iam.list_role_attached_policies(RoleName=s['instance_role'])['AttachedPolicies'],'INSTANCE_ROLE_MUST_HAVE_NO_PERMISSIONS')
        def service_trust(document,service):
            rows=document.get('Statement',[])
            require(rows and all(x.get('Effect')=='Allow' and x.get('Principal')=={'Service':service} and x.get('Action')=='sts:AssumeRole' for x in rows),'EXACT_SERVICE_TRUST_REQUIRED')
        service_trust(role['AssumeRolePolicyDocument'],'ec2.amazonaws.com')
        replication_name=s['replication_role'].rsplit('/',1)[1]
        replication=iam.get_role(RoleName=replication_name)['Role']
        require(replication['Arn']==s['replication_role'],'EXACT_REPLICATION_ROLE_REQUIRED')
        service_trust(replication['AssumeRolePolicyDocument'],'s3.amazonaws.com')
        require(not iam.list_role_attached_policies(RoleName=replication_name)['AttachedPolicies'],'REPLICATION_INLINE_POLICY_REQUIRED')
        names=iam.list_role_policies(RoleName=replication_name)['PolicyNames'];require(0<len(names)<=2,'REPLICATION_INLINE_POLICY_REQUIRED')
        bucket=s['bucket_prefix']+c['project']+'-'+digest(c['project'])[:8];source='arn:aws:s3:::'+bucket;destination='arn:aws:s3:::'+s['replica_bucket']
        allowed={('s3:GetReplicationConfiguration',source),('s3:ListBucket',source),('s3:GetObjectVersionForReplication',source+'/*'),('s3:GetObjectVersionAcl',source+'/*'),('s3:GetObjectVersionTagging',source+'/*'),('s3:ReplicateObject',destination+'/*'),('s3:ReplicateTags',destination+'/*'),('kms:Decrypt',s['kms_key']),('kms:Encrypt',s['replica_kms_key'])}
        observed=set()
        for name in names:
            doc=iam.get_role_policy(RoleName=replication_name,PolicyName=name)['PolicyDocument']
            for statement in doc.get('Statement',[]):
                require(statement.get('Effect')=='Allow' and not any(k in statement for k in ('NotAction','NotResource','Principal')),'REPLICATION_PERMISSION_SCOPE')
                actions=statement['Action'];resources=statement['Resource'];actions=[actions] if isinstance(actions,str) else actions;resources=[resources] if isinstance(resources,str) else resources
                for action in actions:
                    for resource in resources:
                        require((action,resource) in allowed,'REPLICATION_PERMISSION_SCOPE');observed.add((action,resource))
        require(observed==allowed,'REPLICATION_PERMISSION_INCOMPLETE')
        image=self.client('ec2').describe_images(ImageIds=[s['ami']],Owners=[s['ami_owner']])['Images']
        require(len(image)==1 and image[0]['State']=='available' and image[0]['Architecture']=='x86_64','APPROVED_AMI_INVALID')
        self.checked_at=self.auth.clock();self.binding=a;self.credential_binding=digest(self.auth.credentials())
        return {'kind':'CONNECTION','status':'VERIFIED','reason':'LIVE_IDENTITY_AND_SUPPORT_VERIFIED','checked_at':self.checked_at}
    def fresh(self):
        return self.binding==self.auth.check('read') and self.credential_binding==digest(self.auth.credentials()) and 0<=self.auth.clock()-self.checked_at<300
    def empty_bucket(self,bucket):
        c=self.client('s3');args={'Bucket':bucket,'ExpectedBucketOwner':self.auth.c['account_id']}
        require(c.list_objects_v2(**args,MaxKeys=1).get('KeyCount',0)==0,'BUCKET_NOT_EMPTY')
        v=c.list_object_versions(**args,MaxKeys=1)
        require(not v.get('Versions') and not v.get('DeleteMarkers') and not v.get('IsTruncated'),'BUCKET_VERSIONS_PRESENT')
        require(not c.list_multipart_uploads(**args,MaxUploads=1).get('Uploads'),'BUCKET_UPLOADS_PRESENT')
    def inventory(self,managed):
        """Read current EC2/VPC and targeted managed S3; tags never confer ownership."""
        c=self.auth.c;rows=[];ec2=self.client('ec2')
        filters=[{'Name':'tag:Project','Values':[c['project']]},{'Name':'tag:ManagedBy','Values':['Terraform']}]
        for api,field,kind,idkey in [('describe_vpcs','Vpcs','aws_vpc','VpcId'),('describe_instances','Reservations','aws_instance','InstanceId')]:
            token=None
            while True:
                args={'Filters':filters}
                if token:args['NextToken']=token
                response=getattr(ec2,api)(**args);items=response[field]
                if kind=='aws_instance':items=[x for r in items for x in r['Instances'] if x.get('State',{}).get('Name')!='terminated']
                for x in items:rows.append({'type':kind,'id':x[idkey],'owned':(kind,x[idkey]) in managed})
                token=response.get('NextToken')
                if not token:break
        for kind,identity in sorted(managed):
            if kind=='aws_s3_bucket':
                self.client('s3').head_bucket(Bucket=identity,ExpectedBucketOwner=c['account_id'])
                rows.append({'type':kind,'id':identity,'owned':True})
        return rows
