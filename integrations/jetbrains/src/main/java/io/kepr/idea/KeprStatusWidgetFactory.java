package io.kepr.idea;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.Disposer;
import com.intellij.openapi.wm.StatusBar;
import com.intellij.openapi.wm.StatusBarWidget;
import com.intellij.openapi.wm.StatusBarWidgetFactory;
import io.kepr.CliView;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/** "kepr: locked / unlocked / offline" in the status bar, from `kepr status --json` every 10 s. */
public final class KeprStatusWidgetFactory implements StatusBarWidgetFactory {
    @Override public @NotNull String getId() { return "io.kepr.status"; }
    @Override public @NotNull String getDisplayName() { return "kepr"; }
    @Override public boolean isAvailable(@NotNull Project project) { return true; }
    @Override public @NotNull StatusBarWidget createWidget(@NotNull Project project) { return new Widget(); }
    @Override public void disposeWidget(@NotNull StatusBarWidget widget) { Disposer.dispose(widget); }
    @Override public boolean canBeEnabledOn(@NotNull StatusBar statusBar) { return true; }

    private static final class Widget implements StatusBarWidget, StatusBarWidget.TextPresentation {
        private volatile String text = "kepr: …";
        private StatusBar bar;
        private final ScheduledExecutorService poll = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "kepr-status");
            t.setDaemon(true);
            return t;
        });

        @Override public @NotNull String ID() { return "io.kepr.status"; }
        @Override public @Nullable WidgetPresentation getPresentation() { return this; }

        @Override public void install(@NotNull StatusBar statusBar) {
            bar = statusBar;
            poll.scheduleWithFixedDelay(this::refresh, 0, 10, TimeUnit.SECONDS);
        }

        private void refresh() {
            try {
                text = CliView.parseStatus(Cli.run(List.of(Cli.kepr(), "status", "--json"))).text();
            } catch (Exception e) {
                text = "kepr: offline";
            }
            StatusBar b = bar;
            if (b != null) b.updateWidget(ID());
        }

        @Override public @NotNull String getText() { return text; }
        @Override public float getAlignment() { return 0.5f; }
        @Override public @Nullable String getTooltipText() { return "kepr vault state (never shows values)"; }
        @Override public void dispose() { poll.shutdownNow(); bar = null; }
    }
}
