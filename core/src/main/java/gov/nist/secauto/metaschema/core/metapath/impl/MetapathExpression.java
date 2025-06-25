/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.impl;

import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.IExpression;
import gov.nist.secauto.metaschema.core.metapath.InvalidMetapathGrammarException;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.StaticMetapathException;
import gov.nist.secauto.metaschema.core.metapath.antlr.FailingErrorListener;
import gov.nist.secauto.metaschema.core.metapath.antlr.Metapath10;
import gov.nist.secauto.metaschema.core.metapath.antlr.Metapath10Lexer;
import gov.nist.secauto.metaschema.core.metapath.antlr.ParseTreePrinter;
import gov.nist.secauto.metaschema.core.metapath.cst.BuildCSTVisitor;
import gov.nist.secauto.metaschema.core.metapath.cst.CSTPrinter;
import gov.nist.secauto.metaschema.core.metapath.cst.path.ContextItem;
import gov.nist.secauto.metaschema.core.metapath.item.IItem;
import gov.nist.secauto.metaschema.core.metapath.item.ISequence;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.DefaultErrorStrategy;
import org.antlr.v4.runtime.Parser;
import org.antlr.v4.runtime.misc.ParseCancellationException;
import org.antlr.v4.runtime.tree.ParseTree;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Supports compiling and executing Metapath expressions.
 */
public class MetapathExpression
    extends AbstractMetapathExpression {

  /**
   * The Metapath expression identifying the current context node.
   */
  @NonNull
  public static final MetapathExpression CONTEXT_METAPATH
      = new MetapathExpression(".", ContextItem.instance(), StaticContext.instance());
  private static final Logger LOGGER = LogManager.getLogger(MetapathExpression.class);
  @NonNull
  private final IExpression expression;

  /**
   * Compiles a Metapath expression string using the provided static context.
   *
   * @param path
   *          the metapath expression
   * @param context
   *          the static evaluation context
   * @return the compiled expression object
   * @throws InvalidMetapathGrammarException
   *           if an error occurred while compiling the Metapath expression
   */
  @NonNull
  public static MetapathExpression compile(@NonNull String path, @NonNull StaticContext context) {
    @NonNull
    MetapathExpression retval;
    if (".".equals(path)) {
      retval = CONTEXT_METAPATH;
    } else {
      try {
        Metapath10 parser = newParser(path);
        ParseTree tree = ObjectUtils.notNull(parser.metapath());
        logAst(tree);
        IExpression expr = new BuildCSTVisitor(context).visit(tree);
        logCst(expr);
        retval = new MetapathExpression(path, expr, context);
      } catch (StaticMetapathException ex) {
        String message = ex.getMessageText();
        throw new InvalidMetapathGrammarException(
            String.format("Unable to compile path '%s'.%s", path, message == null ? "" : " " + message),
            ex);
      } catch (ParseCancellationException ex) {
        String msg = String.format("Unable to compile Metapath '%s'", path);
        if (LOGGER.isDebugEnabled()) {
          LOGGER.atDebug().withThrowable(ex).log(msg);
        }
        throw new InvalidMetapathGrammarException(msg, ex);
      }
    }
    return retval;
  }

  private static void logCst(@NonNull IExpression expr) {
    if (LOGGER.isDebugEnabled()) {
      LOGGER.atDebug().log(String.format("Metapath CST:%n%s", CSTPrinter.toString(expr)));
    }
  }

  private static void logAst(@NonNull ParseTree tree) {
    if (LOGGER.isDebugEnabled()) {
      try (ByteArrayOutputStream os = new ByteArrayOutputStream()) {
        try (PrintStream ps = new PrintStream(os, true, StandardCharsets.UTF_8)) {
          ParseTreePrinter printer = new ParseTreePrinter(ps);
          printer.print(tree, Metapath10.ruleNames);
          ps.flush();
        }
        LOGGER.atDebug().log(String.format("Metapath AST:%n%s", os.toString(StandardCharsets.UTF_8)));
      } catch (IOException ex) {
        LOGGER.atError().withThrowable(ex).log("An unexpected error occurred while closing the steam.");
      }
    }
  }

  @NonNull
  private static Metapath10 newParser(@NonNull String path) {
    Metapath10Lexer lexer = new Metapath10Lexer(CharStreams.fromString(path));
    lexer.removeErrorListeners();
    lexer.addErrorListener(new FailingErrorListener());

    CommonTokenStream tokens = new CommonTokenStream(lexer);
    Metapath10 parser = new Metapath10(tokens);
    parser.removeErrorListeners();
    parser.addErrorListener(new FailingErrorListener());
    parser.setErrorHandler(new DefaultErrorStrategy() {

      @Override
      public void sync(Parser recognizer) {
        // disable
      }
    });
    return parser;
  }

  /**
   * Construct a new Metapath expression.
   *
   * @param path
   *          the Metapath as a string
   * @param expr
   *          the Metapath as a compiled abstract syntax tree (AST)
   * @param staticContext
   *          the static evaluation context
   */
  protected MetapathExpression(
      @NonNull String path,
      @NonNull IExpression expr,
      @NonNull StaticContext staticContext) {
    super(path, staticContext);
    this.expression = expr;
  }

  @Override
  protected IExpression getExpression() {
    return expression;
  }

  /**
   * Get the compiled compact syntax tree (CST) representation of the Metapath.
   *
   * @return the Metapath CST
   */
  @NonNull
  protected IExpression getCSTNode() {
    return expression;
  }

  @Override
  public String toString() {
    return getPath();
  }

  @Override
  @NonNull
  public <T extends IItem> ISequence<T> evaluate(
      @Nullable IItem focus,
      @NonNull DynamicContext dynamicContext) {
    dynamicContext.pushExecutionStack(this);
    try {
      return ObjectUtils.asType(getCSTNode().accept(dynamicContext, ISequence.of(focus)).reusable());
    } finally {
      dynamicContext.popExecutionStack(this);
    }
  }
}
