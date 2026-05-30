import bashSecureAllowlist from "./shell-guard";
import pathTraversalGuard from "./path-guard";
import { ExtensionAPI } from "@earendil-works/pi-coding-agent";

export default function register(pi: ExtensionAPI) {
  bashSecureAllowlist(pi);
  pathTraversalGuard(pi);
}
