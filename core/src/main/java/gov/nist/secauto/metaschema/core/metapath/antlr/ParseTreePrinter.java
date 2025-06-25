/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.antlr;

import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.RuleContext;
import org.antlr.v4.runtime.tree.ParseTree;
import org.eclipse.jdt.annotation.NotOwning;

import java.io.PrintStream;

import edu.umd.cs.findbugs.annotations.NonNull;

/**
 * Supports walking an ANTLR parse tree to generate a textual representation of
 * the tree.
 */
public class ParseTreePrinter {
  @NotOwning
  @NonNull
  private final PrintStream outputStream;
  private boolean ignoringWrappers = true;

  /**
   * Construct a new concrete syntax tree (CST) printer.
   *
   * @param outputStream
   *          the stream to print to
   */
  public ParseTreePrinter(@NotOwning @NonNull PrintStream outputStream) {
    this.outputStream = outputStream;
  }

  /**
   * Set the behavior for handling wrapper nodes in the CST hierarchy.
   *
   * @param ignoringWrappers
   *          {@code true} if wrappers should be ignored or {@code false}
   *          otherwise
   */
  public void setIgnoringWrappers(boolean ignoringWrappers) {
    this.ignoringWrappers = ignoringWrappers;
  }

  /**
   * Print a given CST {@link ParseTree} using the provided {@code ruleNames}.
   *
   * @param tree
   *          the CST parse tree
   * @param ruleNames
   *          the list of rule names to use for human readability
   */
  @SuppressWarnings("PMD.UseVarargs")
  public void print(ParseTree tree, String[] ruleNames) {
    explore((RuleContext) tree.getPayload(), 0, ruleNames);
  }

  @SuppressWarnings("PMD.UseVarargs")
  private void explore(RuleContext ctx, int indentation, String[] ruleNames) {
    boolean toBeIgnored = ignoringWrappers && ctx.getChildCount() == 1 && ctx.getChild(0) instanceof ParserRuleContext;
    String ruleName = ruleNames[ctx.getRuleIndex()];
    for (int i = 0; i < indentation; i++) {
      outputStream.print("  ");
    }
    outputStream.print(ruleName);
    if (toBeIgnored) {
      outputStream.print("(ignored)");
    }
    outputStream.print(": ");
    outputStream.print(ctx.getText());
    outputStream.println();

    for (int i = 0; i < ctx.getChildCount(); i++) {
      ParseTree element = ctx.getChild(i);
      if (element instanceof RuleContext) {
        explore((RuleContext) element, indentation + 1, ruleNames);
      }
    }
  }
}
