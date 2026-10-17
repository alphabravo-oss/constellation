import { useParams } from "@tanstack/react-router";
import { BaselineWorkflow } from "./BaselineWorkflow";
export function BaselineRuleFormPage() {
 const { ruleId }=useParams({strict:false});
 return <BaselineWorkflow kind={ruleId?"edit":"new"} ruleId={ruleId}/>;
}
