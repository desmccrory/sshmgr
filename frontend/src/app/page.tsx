import { redirect } from "next/navigation";
import { auth } from "@/lib/auth";

export default async function HomePage() {
  const session = await auth();

  if (session) {
    // Redirect authenticated users to user dashboard
    redirect("/user");
  }

  // Redirect unauthenticated users to login
  redirect("/login");
}
