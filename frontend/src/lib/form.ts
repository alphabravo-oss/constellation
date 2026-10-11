import { createFormHook } from "@tanstack/react-form";
import { NumberField, SubmitButton } from "@/components/form/fields";
import { fieldContext, formContext } from "./form-context";

export const { useAppForm, withForm } = createFormHook({
  fieldContext, formContext,
  fieldComponents: { NumberField },
  formComponents: { SubmitButton },
});
export { useStore } from "@tanstack/react-form";
