import markLight from "../../opensecura-mark.svg";
import markDark from "../../opensecura-mark-dark.svg";

export function Mark({ size = 28, onDark = false, className }: { size?: number; onDark?: boolean; className?: string }) {
  return <img src={onDark ? markDark : markLight} width={size} height={size} alt="" className={className} />;
}
