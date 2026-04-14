import "@/styles/globals.css"
import type { AppProps } from "next/app"
import Head from "next/head"
import { ThemeProvider } from "@/components/layout/ThemeContext"

export default function App({ Component, pageProps }: AppProps) {
  return (
    <ThemeProvider>
      <Head>
        <title>4SIC</title>
        <meta name="description" content="4SIC - AI-powered Security Operations Center" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      <Component {...pageProps} />
    </ThemeProvider>
  )
}
