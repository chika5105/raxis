import React from "react";
import ReactDOM from "react-dom/client";

import { App } from "./App";
import { ThemeProvider } from "./lib/theme";
import "./styles/global.css";

const rootEl = document.getElementById("root");
if (!rootEl) throw new Error("root element missing in index.html");

ReactDOM.createRoot(rootEl).render(
  <React.StrictMode>
    <ThemeProvider>
      <App />
    </ThemeProvider>
  </React.StrictMode>,
);
