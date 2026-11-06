import { redirect } from "next/navigation";

export default function SensorHealthRedirect() {
  redirect("/administration/app");
}
