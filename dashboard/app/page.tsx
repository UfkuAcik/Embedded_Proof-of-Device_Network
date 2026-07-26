import { getChatGPTUser } from "./chatgpt-auth";
import { EpdnApp } from "./epdn-app";

export const dynamic = "force-dynamic";

export default async function Home() {
  const user = await getChatGPTUser();

  return (
    <EpdnApp
      viewer={
        user
          ? { displayName: user.displayName, signedIn: true }
          : { displayName: "Guest explorer", signedIn: false }
      }
    />
  );
}
