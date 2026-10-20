import { useParams } from "@tanstack/react-router";
import { useRouteSearchParams } from "@/lib/route-search";
import { ErrorState } from "@/components/ui/states";
import { BaselineWorkflow } from "./BaselineWorkflow";
export function BaselineActionFormPage() {
 const { action }=useParams({strict:false});const [params]=useRouteSearchParams();
 return action==="mode"||action==="delete-rule"?<BaselineWorkflow kind={action} ruleId={params.get("rule")??""} desiredMode={params.get("mode")??""}/>:<ErrorState title="Select a supported process baseline action."/>;
}
