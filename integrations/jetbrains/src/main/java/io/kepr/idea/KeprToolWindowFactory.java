package io.kepr.idea;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.ui.components.JBList;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.content.ContentFactory;
import io.kepr.CliView;
import java.awt.BorderLayout;
import java.awt.datatransfer.StringSelection;
import java.util.List;
import javax.swing.DefaultListModel;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.SwingUtilities;
import org.jetbrains.annotations.NotNull;

/**
 * Credential names with type, tags and expiry. "Copy" runs `kepr copy NAME` (the CLI puts the value on the
 * clipboard and clears it later); this plugin never reads or shows a value. Sealed keys have no copy.
 */
public final class KeprToolWindowFactory implements ToolWindowFactory {
    @Override
    public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
        DefaultListModel<CliView.Cred> model = new DefaultListModel<>();
        JBList<CliView.Cred> list = new JBList<>(model);
        list.setCellRenderer((l, c, i, sel, focus) -> new javax.swing.JLabel(c.name() + "  —  " + c.subtitle()));
        JButton refresh = new JButton("Refresh");
        JButton copy = new JButton("Copy");
        JPanel bar = new JPanel();
        bar.add(refresh);
        bar.add(copy);
        JPanel root = new JPanel(new BorderLayout());
        root.add(new JBScrollPane(list), BorderLayout.CENTER);
        root.add(bar, BorderLayout.SOUTH);

        Runnable load = () -> new Thread(() -> {
            try {
                List<CliView.Cred> creds = CliView.parseList(Cli.run(List.of(Cli.kepr(), "ls", "--json")));
                SwingUtilities.invokeLater(() -> {
                    model.clear();
                    creds.forEach(model::addElement);
                });
            } catch (Exception e) {
                SwingUtilities.invokeLater(model::clear);
            }
        }, "kepr-list").start();
        refresh.addActionListener(e -> load.run());
        copy.addActionListener(e -> {
            CliView.Cred c = list.getSelectedValue();
            List<String> argv = c != null && c.copyable() ? CliView.copyCommand(Cli.kepr(), c.name()) : null;
            if (argv == null) return;
            new Thread(() -> {
                try {
                    Cli.run(argv);
                } catch (Exception ignored) {
                    // kepr refused or is locked: nothing was copied
                }
            }, "kepr-copy").start();
        });
        toolWindow.getContentManager().addContent(ContentFactory.getInstance().createContent(root, "", false));
        load.run();
    }
}
