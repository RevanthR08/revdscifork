import { AuthPage } from "@/components/ui/auth-page";
import Head from "next/head";

export default function Auth() {
  return (
    <>
      <Head>
        <title>Sign In | Asme Platform</title>
        <meta name="description" content="Sign in or join Asme Platform to access your SOC dashboard and forensic analysis." />
      </Head>
      <AuthPage />
    </>
  );
}
