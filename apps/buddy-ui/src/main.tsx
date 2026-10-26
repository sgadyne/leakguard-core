import React from "react";
import { createRoot } from "react-dom/client";
import { CacheProvider } from "@emotion/react";
import createCache from "@emotion/cache";
import App from "./App";
import "./styles.css";
const nonce = document.querySelector<HTMLMetaElement>('meta[name="buddy-style-nonce"]')?.content;
createRoot(document.getElementById("root")!).render(<React.StrictMode><CacheProvider value={createCache({ key: "mui", nonce })}><App /></CacheProvider></React.StrictMode>);