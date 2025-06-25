/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.metapath.cst;

import gov.nist.secauto.metaschema.core.metapath.IExpression;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.StaticMetapathException;
import gov.nist.secauto.metaschema.core.metapath.antlr.AbstractAstVisitor;
import gov.nist.secauto.metaschema.core.metapath.antlr.Metapath10;
import gov.nist.secauto.metaschema.core.util.ObjectUtils;

import org.antlr.v4.runtime.ParserRuleContext;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.TerminalNode;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.xml.namespace.QName;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;

/**
 * Provides utility methods for processing Metapath abstract syntax tree (AST)
 * nodes to produce a compact syntax tree (CST).
 * <p>
 * This base class implements common visitor patterns for transforming AST nodes
 * into a more compact representation. The CST is optimized for efficient
 * evaluation of Metapath expressions.
 * <p>
 * Key utility methods include:
 * <ul>
 * <li>{@link #nairyToList} - Processes n-airy expressions into a list
 * <li>{@link #nairyToCollection} - Processes n-airy expressions into a
 * collection
 * <li>{@link #handleNAiryCollection} - Handles n-airy expressions with
 * operators
 * <li>{@link #handleGroupedNAiry} - Processes grouped n-airy expressions
 * </ul>
 */
@SuppressWarnings({
    "PMD.CouplingBetweenObjects"
})
public abstract class AbstractCSTVisitorBase
    extends AbstractAstVisitor<IExpression> {

  private static final Pattern QUALIFIED_NAME_PATTERN = Pattern.compile("^Q\\{([^}]*)\\}(.+)$");

  /**
   * Get the QName for an
   * <a href="https://www.w3.org/TR/xpath-31/#dt-expanded-qname">expanded
   * QName</a>.
   *
   * @param eqname
   *          the expanded QName
   * @param context
   *          the Metapath evaluation static context
   * @param requireNamespace
   *          if {@code true} require the resulting QName to have a namespace, or
   *          {@code false} otherwise
   * @return the QName
   * @throws StaticMetapathException
   *           if the expanded QName prefix is not bound or if the resulting
   *           namespace is invalid
   */
  @SuppressWarnings({ "PMD.CyclomaticComplexity" })
  @NonNull
  static QName toQName(@NonNull Metapath10.EqnameContext eqname, @NonNull StaticContext context,
      boolean requireNamespace) {
    String namespaceUri;
    String localName;
    TerminalNode node;
    if ((node = eqname.URIQualifiedName()) != null) {
      // BracedURILiteral - Q{uri}name -
      // https://www.w3.org/TR/xpath-31/#doc-xpath31-BracedURILiteral
      Matcher matcher = QUALIFIED_NAME_PATTERN.matcher(node.getText());
      if (!matcher.matches()) {
        // the syntax should always match above, since ANTLR is parsing it
        throw new IllegalStateException();
      }
      namespaceUri = matcher.group(1);
      localName = matcher.group(2);
    } else {
      String prefix;
      String[] tokens = eqname.getText().split(":", 2);
      if (tokens.length == 2) {
        // lexical QName with prefix - prefix:name
        // https://www.w3.org/TR/xpath-31/#dt-qname
        prefix = ObjectUtils.notNull(tokens[0]);
        localName = tokens[1];
      } else {
        // lexical QName without prefix - name
        // https://www.w3.org/TR/xpath-31/#dt-qname
        prefix = "";
        localName = tokens[0];
      }
      namespaceUri = context.lookupNamespaceForPrefix(prefix);
      if (namespaceUri == null && requireNamespace) {
        throw new StaticMetapathException(
            StaticMetapathException.PREFIX_NOT_EXPANDABLE,
            String.format("The static context does not have a namespace URI configured for prefix '%s'.", prefix));
      }
    }

    QName retval;
    if (namespaceUri == null) {
      retval = new QName(localName);
    } else {
      if ("http://www.w3.org/2000/xmlns/".equals(namespaceUri)) {
        throw new StaticMetapathException(StaticMetapathException.NAMESPACE_MISUSE,
            "The namespace of an expanded QName cannot be: http://www.w3.org/2000/xmlns/");
      }
      retval = new QName(namespaceUri, localName);
    }
    return retval;
  }

  @SuppressWarnings("null")
  @Override
  @NonNull
  public IExpression visit(ParseTree tree) {
    assert tree != null;
    return super.visit(tree);
  }

  /**
   * Parse the provided context as an n-airy phrase.
   *
   * @param <CONTEXT>
   *          the Java type of the antlr context to parse
   * @param <T>
   *          the Java type of the child expressions produced by this parser
   * @param <R>
   *          the Java type of the outer expression produced by the parser
   * @param context
   *          the antlr context to parse
   * @param startIndex
   *          the child index to start parsing on
   * @param step
   *          the increment to advance while parsing child expressions
   * @param parser
   *          a binary function used to produce child expressions
   * @return the outer expression or {@code null} if no children exist to parse
   */
  @Nullable
  protected <CONTEXT extends ParserRuleContext, T, R>
      List<R> nairyToList(
          @NonNull CONTEXT context,
          int startIndex,
          int step,
          @NonNull BiFunction<CONTEXT, Integer, R> parser) {
    int numChildren = context.getChildCount();

    List<R> retval = null;
    if (startIndex < numChildren) {
      retval = new ArrayList<>((numChildren - startIndex) / step);
      for (int idx = startIndex; idx < numChildren; idx += step) {
        R result = parser.apply(context, idx);
        retval.add(result);
      }
    }
    return retval;
  }

  /**
   * Parse the provided context as an n-airy phrase.
   *
   * @param <CONTEXT>
   *          the Java type of the antlr context to parse
   * @param <T>
   *          the Java type of the child expressions produced by this parser
   * @param <R>
   *          the Java type of the outer expression produced by the parser
   * @param context
   *          the antlr context to parse
   * @param startIndex
   *          the child index to start parsing on
   * @param step
   *          the increment to advance while parsing child expressions
   * @param parser
   *          a binary function used to produce child expressions
   * @param supplier
   *          a function used to produce the other expression
   * @return the outer expression or {@code null} if no children exist to parse
   */
  @Nullable
  protected <CONTEXT extends ParserRuleContext, T, R>
      R nairyToCollection(
          @NonNull CONTEXT context,
          int startIndex,
          int step,
          @NonNull BiFunction<CONTEXT, Integer, T> parser,
          @NonNull Function<List<T>, R> supplier) {
    int numChildren = context.getChildCount();

    R retval = null;
    if (startIndex < numChildren) {
      List<T> children = new ArrayList<>((numChildren - startIndex) / step);
      for (int idx = startIndex; idx < numChildren; idx += step) {
        T result = parser.apply(context, idx);
        children.add(result);
      }
      retval = supplier.apply(children);
    }
    return retval;
  }

  /**
   * Parse the provided context as an n-airy phrase, which will be one of the
   * following.
   * <ol>
   * <li>A single <code>expr</code> for which that expr will be returned
   * <li><code>left (operator right)*</code> for which a collection of the left
   * and right members will be returned based on what is provided by the supplier.
   * </ol>
   *
   * @param <CONTEXT>
   *          the context type to parse
   * @param context
   *          the context instance
   * @param supplier
   *          a supplier that will instantiate an expression based on the provided
   *          parsed collection
   * @return the left expression or the supplied expression for a collection
   */
  @NonNull
  protected <CONTEXT extends ParserRuleContext> IExpression
      handleNAiryCollection(
          @NonNull CONTEXT context,
          @NonNull Function<List<IExpression>, IExpression> supplier) {
    return handleNAiryCollection(context, 1, 2, (ctx, idx) -> {
      // skip operator, since we know what it is
      ParseTree tree = ctx.getChild(idx + 1);
      return tree.accept(this);
    }, supplier);
  }

  /**
   * Parse the provided context as an n-airy phrase, which will be one of the
   * following.
   * <ol>
   * <li><code>expr</code> for which the expr will be returned.
   * <li><code>left</code> plus a number of additional recurring tokens as defined
   * by the <em>step</em>.
   * </ol>
   * <p>
   * In the second case, the supplier will be used to generate an expression from
   * the collection of tuples.
   *
   * @param <CONTEXT>
   *          the context type to parse
   * @param context
   *          the context instance
   * @param startIndex
   *          the starting context child position
   * @param step
   *          the amount to advance the loop over the context children
   * @param parser
   *          a binary function used to parse the context children
   * @param supplier
   *          a supplier that will instantiate an expression based on the provided
   *          collection
   * @return the left expression or the supplied expression for a collection
   */
  @NonNull
  protected <CONTEXT extends ParserRuleContext> IExpression
      handleNAiryCollection(
          @NonNull CONTEXT context,
          int startIndex,
          int step,
          @NonNull BiFunction<CONTEXT, Integer, IExpression> parser,
          @NonNull Function<List<IExpression>, IExpression> supplier) {
    int numChildren = context.getChildCount();

    if (numChildren == 0) {
      throw new IllegalStateException("there should always be a child expression");
    }
    if (startIndex > numChildren) {
      throw new IllegalStateException("Start index is out of bounds");
    }

    ParseTree leftTree = context.getChild(0);
    @SuppressWarnings({ "null" })
    @NonNull
    IExpression leftResult = leftTree.accept(this);

    IExpression retval;
    if (numChildren == 1) {
      retval = leftResult;
    } else {
      List<IExpression> children = new ArrayList<>(numChildren - 1 / step);
      children.add(leftResult);
      for (int i = startIndex; i < numChildren; i = i + step) {
        IExpression result = parser.apply(context, i);
        children.add(result);
      }
      IExpression result = ObjectUtils.notNull(supplier.apply(children));
      retval = result;
    }
    return retval;
  }

  /**
   * Parse the provided context as a simple n-airy phrase, which will be one of
   * the following.
   * <ol>
   * <li><code>expr</code> for which the expr will be returned
   * <li><code>left (operator right)*</code> for which a collection of the left
   * and right members will be returned based on what is provided by the supplier.
   * </ol>
   * <p>
   * In the second case, the supplier will be used to generate an expression from
   * the collection of tuples.
   *
   * @param <CONTEXT>
   *          the context type to parse
   * @param context
   *          the context instance
   * @param startingIndex
   *          the index of the first child expression, which must be a
   *          non-negative value that is less than the number of children
   * @param step
   *          the amount to advance the loop over the context children
   * @param parser
   *          a trinary function used to parse the context children and supply a
   *          result
   * @return the left expression or the supplied expression
   */
  protected <CONTEXT extends ParserRuleContext> IExpression handleGroupedNAiry(
      @NonNull CONTEXT context,
      int startingIndex,
      int step,
      @NonNull ITriFunction<CONTEXT, Integer, IExpression, IExpression> parser) {
    int numChildren = context.getChildCount();
    if (startingIndex >= numChildren) {
      throw new IndexOutOfBoundsException(
          String.format("The starting index '%d' exceeds the child count '%d'",
              startingIndex,
              numChildren));
    }

    IExpression retval = null;
    if (numChildren > 0) {
      ParseTree leftTree = context.getChild(startingIndex);
      retval = ObjectUtils.notNull(leftTree.accept(this));

      for (int i = startingIndex + 1; i < numChildren; i = i + step) {
        retval = parser.apply(context, i, retval);
      }
    }
    return retval;
  }

  @FunctionalInterface
  interface ITriFunction<T, U, V, R> {

    R apply(T argT, U argU, V argV);

    default <W> ITriFunction<T, U, V, W> andThen(Function<? super R, ? extends W> after) {
      Objects.requireNonNull(after);
      return (T t, U u, V v) -> after.apply(apply(t, u, v));
    }
  }
}
