/*
 * Created by JFormDesigner on Fri Dec 30 09:58:23 ICT 2022
 */

package org.example.view.view;

import javax.swing.*;
import javax.swing.GroupLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.io.FileNotFoundException;

import static org.example.view.helper.Cer.changePasswordKeyStore;

public class ChangePINScreen extends JPanel {
    private JPanel panel1;
    private JLabel oldPINLabel;
    private JTextField oldPINTextField;
    private JLabel newPINLabel;
    private JTextField newPINTextField;
    private JLabel retypeNewPINLabel;
    private JTextField retypeNewPINTextField;
    private JButton applyNewPINButton;
    private JButton chooseFileButton;  // Added file chooser button
    private JTextField selectedFilePath;  // Display selected file path

    public ChangePINScreen() {
        initComponents();
    }

    private void initComponents() {
        panel1 = new JPanel();
        oldPINLabel = new JLabel();
        oldPINTextField = new JTextField();
        newPINLabel = new JLabel();
        newPINTextField = new JTextField();
        retypeNewPINLabel = new JLabel();
        retypeNewPINTextField = new JTextField();
        applyNewPINButton = new JButton();
        chooseFileButton = new JButton("Choose File");
        selectedFilePath = new JTextField();
        selectedFilePath.setEditable(false);
        //======== panel1 ========
        {

            //---- oldPINLabel ----
            oldPINLabel.setText("Nh\u1eadp PIN c\u0169:");

            //---- newPINLabel ----
            newPINLabel.setText("Nh\u1eadp PIN m\u1edbi");

            //---- retypeNewPINLabel ----
            retypeNewPINLabel.setText("Nh\u1eadp l\u1ea1i PIN m\u1edbi");

            //---- applyNewPINButton ----
            applyNewPINButton.setText("\u00c1p d\u1ee5ng");

            //---- chooseFileButton ----
            chooseFileButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    JFileChooser fileChooser = new JFileChooser();
                    int result = fileChooser.showOpenDialog(null);
                    if (result == JFileChooser.APPROVE_OPTION) {
                        String filePath = fileChooser.getSelectedFile().getAbsolutePath();
                        selectedFilePath.setText(filePath);
                    }
                }
            });
            applyNewPINButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    String oldPIN = oldPINTextField.getText();
                    String newPIN = newPINTextField.getText();
                    String retypeNewPIN = retypeNewPINTextField.getText();


                    // Check if any of the password fields is empty
                    if (oldPIN.isEmpty() || newPIN.isEmpty() || retypeNewPIN.isEmpty()) {
                        JOptionPane.showMessageDialog(ChangePINScreen.this, "Please fill in all password fields.");
                    }

                    // Check if new PIN and retype new PIN match
                    if (!newPIN.equals(retypeNewPIN)) {
                        JOptionPane.showMessageDialog(ChangePINScreen.this, "PINs do not match. Please re-enter.");
                    }

                    // Check if the new PIN has a length greater than 6
                    if (oldPIN.length() >= 6) {
                        if (newPIN.length() >= 6) {
                            if (retypeNewPIN.length() >= 6) {
                                if (newPIN.equals(retypeNewPIN)) {
                                    if (!selectedFilePath.getText().isEmpty()) {
                                        try {
                                            changePasswordKeyStore(new FileInputStream(selectedFilePath.getText()), oldPIN, newPIN);
                                        } catch (FileNotFoundException ex) {
                                            throw new RuntimeException(ex);
                                        }
                                    } else {
                                        JOptionPane.showMessageDialog(ChangePINScreen.this, "Please choose a file.");
                                    }
                                } else {
                                    JOptionPane.showMessageDialog(ChangePINScreen.this, "PINs do not match. Please re-enter.");
                                }
                            } else {
                                JOptionPane.showMessageDialog(ChangePINScreen.this, "New PIN must have a length greater than 6.");
                            }
                        } else {
                            JOptionPane.showMessageDialog(ChangePINScreen.this, "New PIN must have a length greater than 6.");
                        }

                    } else {
                        JOptionPane.showMessageDialog(ChangePINScreen.this, "Old PIN must have a length greater than 6.");
                    }

                    JOptionPane.showMessageDialog(ChangePINScreen.this, "PIN changed successfully.");
                }
            });

            GroupLayout panel1Layout = new GroupLayout(panel1);
            panel1.setLayout(panel1Layout);
            panel1Layout.setHorizontalGroup(panel1Layout.createParallelGroup().addGroup(panel1Layout.createSequentialGroup().addGap(32, 32, 32).addGroup(panel1Layout.createParallelGroup().addGroup(panel1Layout.createSequentialGroup().addComponent(newPINLabel).addGap(18, 18, 18).addComponent(newPINTextField, GroupLayout.PREFERRED_SIZE, 199, GroupLayout.PREFERRED_SIZE).addContainerGap(201, Short.MAX_VALUE)).addGroup(panel1Layout.createSequentialGroup().addComponent(oldPINLabel).addGap(18, 18, 18).addComponent(oldPINTextField, GroupLayout.DEFAULT_SIZE, 199, Short.MAX_VALUE).addGap(206, 206, 206)).addGroup(panel1Layout.createSequentialGroup().addGroup(panel1Layout.createParallelGroup().addComponent(applyNewPINButton).addGroup(panel1Layout.createSequentialGroup().addComponent(retypeNewPINLabel).addGap(18, 18, 18).addComponent(retypeNewPINTextField, GroupLayout.PREFERRED_SIZE, 200, GroupLayout.PREFERRED_SIZE))).addGap(0, 185, Short.MAX_VALUE)).addGroup(GroupLayout.Alignment.TRAILING, panel1Layout.createSequentialGroup().addGroup(panel1Layout.createParallelGroup().addComponent(selectedFilePath, GroupLayout.Alignment.TRAILING).addComponent(chooseFileButton, GroupLayout.Alignment.TRAILING)).addGap(176, 176, 176)))));
            panel1Layout.setVerticalGroup(panel1Layout.createParallelGroup().addGroup(panel1Layout.createSequentialGroup().addGap(30, 30, 30).addGroup(panel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(oldPINLabel).addComponent(oldPINTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)).addGap(24, 24, 24).addGroup(panel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(newPINLabel).addComponent(newPINTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)).addGap(25, 25, 25).addGroup(panel1Layout.createParallelGroup(GroupLayout.Alignment.BASELINE).addComponent(retypeNewPINLabel).addComponent(retypeNewPINTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)).addGap(18, 18, 18).addComponent(applyNewPINButton).addPreferredGap(LayoutStyle.ComponentPlacement.UNRELATED).addComponent(chooseFileButton).addPreferredGap(LayoutStyle.ComponentPlacement.RELATED).addComponent(selectedFilePath).addContainerGap(12, Short.MAX_VALUE)));
        }
        // JFormDesigner - End of component initialization  //GEN-END:initComponents
    }

    public JPanel getPanel() {
        return panel1;
    }
}
