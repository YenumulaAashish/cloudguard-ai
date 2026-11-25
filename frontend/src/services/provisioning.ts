import Ajv2020 from 'ajv/dist/2020';
import schema from '../data/phase6-public.schema.json';
export const actions=['session','login','logout','status','preview','deploy','drift','reconcile','delete-preview','recover','simulate-drift'] as const;
export type Action=typeof actions[number];
export interface Config {project:string;region:string;vpc:{enabled:boolean;cidr:string;subnet_cidr:string};ec2:{enabled:boolean;instance_type:string;ami:string;root_gb:number;hours:number};s3:{enabled:boolean;storage_gb:number;requests:number;transfer_gb:number};budget_usd:string}
export const initialConfig:Config={project:'capstone',region:'ap-south-1',vpc:{enabled:true,cidr:'10.40.0.0/16',subnet_cidr:'10.40.1.0/24'},ec2:{enabled:false,instance_type:'t3.micro',ami:'mock-al2023',root_gb:8,hours:24},s3:{enabled:true,storage_gb:1,requests:1000,transfer_gb:0},budget_usd:'5.00'};
export interface Job {kind:'JOB';id:string;purpose:string;mode:'MOCK_ONLY';status:string;can_deploy:boolean;changes:Record<string,number>;gates:Record<string,{status:string;reason:string;passed?:number;failed?:number;skipped?:number;failure_reasons?:{rule_id:string;reason_code:string;count:number}[]}>;cost:{status:string;estimate_usd:string|null;limit_usd:string;reason:string};confirmation:string;context_reason:string;expires_at:number;created_at:number}
export interface Snapshot {kind:'STATUS';mode:'MOCK_ONLY';inventory:{id:string;resource_type:string;status:string;owned:boolean}[];history:Job[];audit:{sequence:number;kind:string;job:string|null;serial:number;recorded_at:number}[];state_serial:number;busy:boolean;budget_limit_usd:string}
export interface Drift {kind:'DRIFT';mode:'MOCK_ONLY';status:string;reason:string;changes:{resource_id:string;resource_type:string;kind:string;fields:string[]}[];alerts:{id:string;kind:string;status:string}[]}
export type Data=Job|Snapshot|Drift|{kind:'SESSION';authenticated:boolean;csrf:string}|{kind:'LOGOUT'};
const validate=new Ajv2020({strict:true}).compile(schema);
export async function request(action:Action,body:unknown={},csrf=''):Promise<Data> {
 if(!actions.includes(action))throw Error('Request denied');
 const response=await fetch('/api/phase6/' + action,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json','X-CloudGuard-Client':'phase6-mock','X-CSRF-Token':csrf},body:JSON.stringify(body),signal:AbortSignal.timeout(300000)});
 const text=await response.text();if(text.length>131072)throw Error('Request denied');const value=JSON.parse(text);
 if(!validate(value)||!response.ok||value.ok!==true)throw Error('Request denied');
 return value.data as Data;
}
