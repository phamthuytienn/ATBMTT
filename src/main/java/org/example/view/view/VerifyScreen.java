/*
 * Created by JFormDesigner on Tue Jan 03 23:31:41 ICT 2023
 */

package org.example.view.view;


import javax.swing.*;
import javax.swing.GroupLayout;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;
import javax.swing.filechooser.FileFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

import static org.example.view.helper.Cer.checkDigitalSignPDF;

/**
 * @author howl
 */
public class VerifyScreen extends JPanel {
    public VerifyScreen() {
        initComponents();
    }

    private void initComponents() {
        // JFormDesigner - Component initialization - DO NOT MODIFY  //GEN-BEGIN:initComponents  @formatter:off
        verifyPanel = new JPanel();
        label1 = new JLabel();
        getFileButton = new JButton();
        label2 = new JLabel();
        statusLabel = new JLabel();
        fileLinkLabel = new JLabel();

        //======== verifyPanel ========
        {
            getFileButton.setBackground(Color.white);
            //---- label1 ----
            label1.setText("Ch\u1ecdn file c\u1ea7n ki\u1ec3m tra:");

            //---- getFileButton ----
            getFileButton.setText("Ch\u1ecdn file");

            //---- label2 ----
            label2.setText("Tr\u1ea1ng th\u00e1i:");

            GroupLayout panel1Layout = new GroupLayout(verifyPanel);

            verifyPanel.setBackground(Color.pink);
            LineBorder lineBorder = new LineBorder(Color.GRAY, 2);

            // Tạo TitledBorder với màu xám và độ dày là 2 pixel
            TitledBorder titledBorder = BorderFactory.createTitledBorder(lineBorder, "Kiểm tra trạng thái của file", TitledBorder.CENTER, TitledBorder.TOP);
            verifyPanel.setBorder(titledBorder);
            verifyPanel.setLayout(panel1Layout);
            panel1Layout.setHorizontalGroup(
                panel1Layout.createParallelGroup()
                    .addGroup(panel1Layout.createSequentialGroup()
                        .addGap(14, 14, 14)
                        .addGroup(panel1Layout.createParallelGroup()
                            .addComponent(label1)
                            .addComponent(label2))
                        .addGap(18, 18, 18)
                        .addGroup(panel1Layout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                            .addComponent(getFileButton, GroupLayout.DEFAULT_SIZE, 157, Short.MAX_VALUE)
                            .addComponent(statusLabel, GroupLayout.DEFAULT_SIZE, 157, Short.MAX_VALUE))
                        .addGap(18, 18, 18)
                        .addComponent(fileLinkLabel)
                        .addContainerGap(284, Short.MAX_VALUE))
            );
            panel1Layout.setVerticalGroup(
                panel1Layout.createParallelGroup()
                    .addGroup(panel1Layout.createSequentialGroup()
                        .addGap(15, 15, 15)
                        .addGroup(panel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(label1)
                            .addComponent(getFileButton)
                            .addComponent(fileLinkLabel))
                        .addGap(18, 18, 18)
                        .addGroup(panel1Layout.createParallelGroup()
                            .addComponent(label2)
                            .addComponent(statusLabel))
                        .addContainerGap(31, Short.MAX_VALUE))
            );
        }

        getFileButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JFileChooser file = new JFileChooser();
                file.addChoosableFileFilter(new FileFilter() {
                    @Override
                    public boolean accept(File f) {
                        return f.getName().toLowerCase().endsWith(".pdf");
                    }

                    @Override
                    public String getDescription() {
                        return "File PDF";
                    }
                });
                file.showOpenDialog(null);
                File selectedFile = file.getSelectedFile();
                String link = selectedFile.getAbsolutePath();
                fileLinkLabel.setText(link);
                try {
                    boolean b = checkDigitalSignPDF(new FileInputStream(link),"sig");
                    if(b) {
                        statusLabel.setText("File đã được ký");
                    } else {
                        statusLabel.setText("File chưa được ký");
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(null,"Không thể đọc file, vui lòng kiểm tra lại");
                }
            }
        });
        // JFormDesigner - End of component initialization  //GEN-END:initComponents  @formatter:on
    }

    // JFormDesigner - Variables declaration - DO NOT MODIFY  //GEN-BEGIN:variables  @formatter:off
    private JPanel verifyPanel;
    private JLabel label1;
    private JButton getFileButton;
    private JLabel label2;
    private JLabel statusLabel;
    private JLabel fileLinkLabel;
    // JFormDesigner - End of variables declaration  //GEN-END:variables  @formatter:on
    public JPanel getPanel() {
        return verifyPanel;
    }
}
