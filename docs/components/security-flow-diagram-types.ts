import type { Mode } from "./security-flow-data";

export type SecurityFlowDiagramProps = {
  mode: Mode;
  selected: string;
  cloud: string;
  localReady: boolean;
  onSelect: (id: string) => void;
};
