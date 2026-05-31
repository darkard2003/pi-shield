import bashSecureAllowlist from "./shell-guard";
import pathTraversalGuard from "./path-guard";
import registerCustomTools from "./custom-tools";
import { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function register(pi: ExtensionAPI) {
  bashSecureAllowlist(pi);
  pathTraversalGuard(pi);
  registerCustomTools(pi);
}
