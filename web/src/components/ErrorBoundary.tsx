import { Component, type ErrorInfo, type ReactNode } from "react";

/** Keeps one bad render from blanking the whole SPA.
 *
 *  React unmounts the entire tree when a render throws and nothing catches it,
 *  so a malformed field in one scan payload used to leave the user staring at
 *  an empty page with no way back. */
export class ErrorBoundary extends Component<
  { children: ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };

  static getDerivedStateFromError(error: Error) {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Sphinx UI crashed", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div className="empty" role="alert">
        <strong>Something in the interface broke</strong>
        The scan itself may have been fine — this is a display error. Reload, or
        try a different URL.
        <p className="crash-detail">{this.state.error.message}</p>
        <button
          type="button"
          className="ghost-button"
          onClick={() => this.setState({ error: null })}
        >
          Try again
        </button>
      </div>
    );
  }
}
