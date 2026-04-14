import { AuthPage } from "@/components/ui/auth-page";
import Head from "next/head";

export default function Auth() {
  return (
    <>
      <Head>
        <title>Sign In | 4SIC</title>
        <meta name="description" content="Sign in to 4SIC to access your SOC dashboard and forensic analysis workspace." />
      </Head>
      <AuthPage />
    </>
  );
}
