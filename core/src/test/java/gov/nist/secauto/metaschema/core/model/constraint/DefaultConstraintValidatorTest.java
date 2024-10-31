/*
 * SPDX-FileCopyrightText: none
 * SPDX-License-Identifier: CC0-1.0
 */

package gov.nist.secauto.metaschema.core.model.constraint;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasItem;
import static org.hamcrest.Matchers.hasProperty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

import gov.nist.secauto.metaschema.core.datatype.markup.MarkupLine;
import gov.nist.secauto.metaschema.core.metapath.DynamicContext;
import gov.nist.secauto.metaschema.core.metapath.StaticContext;
import gov.nist.secauto.metaschema.core.metapath.format.IPathFormatter;
import gov.nist.secauto.metaschema.core.metapath.item.IItemVisitor;
import gov.nist.secauto.metaschema.core.metapath.item.atomic.IStringItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.IFlagNodeItem;
import gov.nist.secauto.metaschema.core.metapath.item.node.MockNodeItemFactory;
import gov.nist.secauto.metaschema.core.model.IFlagDefinition;
import gov.nist.secauto.metaschema.core.model.ISource;
import gov.nist.secauto.metaschema.core.util.CollectionUtil;

import org.junit.jupiter.api.Test;

import java.net.URI;
import java.util.List;

import javax.xml.namespace.QName;

import edu.umd.cs.findbugs.annotations.NonNull;

@SuppressWarnings("PMD.TooManyStaticImports")
class DefaultConstraintValidatorTest {
  private static final String NS = URI.create("http://example.com/ns").toASCIIString();

  @NonNull
  private static QName qname(@NonNull String name) {
    return new QName(NS, name);
  }

  @SuppressWarnings("null")
  @Test
  void testAllowedValuesAllowOther() {
    MockNodeItemFactory itemFactory = new MockNodeItemFactory();

    IFlagNodeItem flag = itemFactory.flag(qname("value"), IStringItem.valueOf("value"));

    IFlagDefinition flagDefinition = mock(IFlagDefinition.class);

    ISource source = mock(ISource.class);

    IAllowedValuesConstraint allowedValues = IAllowedValuesConstraint.builder()
        .source(source)
        .allowedValue(IAllowedValue.of(
            "other",
            MarkupLine.fromMarkdown("some documentation"),
            "1.0.0"))
        .allowsOther(true)
        .build();

    doReturn(flagDefinition).when(flag).getDefinition();
    doReturn("flag/path").when(flag).toPath(any(IPathFormatter.class));

    doReturn(CollectionUtil.emptyMap()).when(flagDefinition).getLetExpressions();
    doReturn(CollectionUtil.singletonList(allowedValues)).when(flagDefinition).getAllowedValuesConstraints();
    doReturn(CollectionUtil.emptyList()).when(flagDefinition).getExpectConstraints();
    doReturn(CollectionUtil.emptyList()).when(flagDefinition).getMatchesConstraints();
    doReturn(CollectionUtil.emptyList()).when(flagDefinition).getIndexHasKeyConstraints();

    doReturn(StaticContext.instance()).when(source).getStaticContext();

    FindingCollectingConstraintValidationHandler handler = new FindingCollectingConstraintValidationHandler();
    DefaultConstraintValidator validator = new DefaultConstraintValidator(handler);
    DynamicContext dynamicContext = new DynamicContext();
    validator.validate(flag, dynamicContext);
    validator.finalizeValidation(dynamicContext);

    assertTrue(handler.isPassing(), "doesn't pass");
  }

  @SuppressWarnings("null")
  @Test
  void testAllowedValuesMultipleAllowOther() {
    MockNodeItemFactory itemFactory = new MockNodeItemFactory();

    IFlagNodeItem flag = itemFactory.flag(qname("value"), IStringItem.valueOf("value"));

    IFlagDefinition flagDefinition = mock(IFlagDefinition.class);

    ISource source = mock(ISource.class);

    IAllowedValuesConstraint allowedValues1 = IAllowedValuesConstraint.builder()
        .source(source)
        .allowedValue(IAllowedValue.of(
            "other",
            MarkupLine.fromMarkdown("some documentation"),
            "1.0.0"))
        .allowsOther(true)
        .build();
    IAllowedValuesConstraint allowedValues2 = IAllowedValuesConstraint.builder()
        .source(source)
        .allowedValue(IAllowedValue.of(
            "other2",
            MarkupLine.fromMarkdown("some documentation"), null))
        .allowsOther(true)
        .build();

    List<? extends IAllowedValuesConstraint> allowedValuesConstraints
        = List.of(allowedValues1, allowedValues2);

    doReturn(flagDefinition).when(flag).getDefinition();
    doReturn("flag/path").when(flag).toPath(any(IPathFormatter.class));

    doReturn(CollectionUtil.emptyMap()).when(flagDefinition).getLetExpressions();
    doReturn(allowedValuesConstraints).when(flagDefinition).getAllowedValuesConstraints();
    doReturn(CollectionUtil.emptyList()).when(flagDefinition).getExpectConstraints();
    doReturn(CollectionUtil.emptyList()).when(flagDefinition).getMatchesConstraints();
    doReturn(CollectionUtil.emptyList()).when(flagDefinition).getIndexHasKeyConstraints();

    doReturn(StaticContext.instance()).when(source).getStaticContext();

    FindingCollectingConstraintValidationHandler handler = new FindingCollectingConstraintValidationHandler();
    DefaultConstraintValidator validator = new DefaultConstraintValidator(handler);
    DynamicContext dynamicContext = new DynamicContext();
    validator.validate(flag, dynamicContext);
    validator.finalizeValidation(dynamicContext);

    assertTrue(handler.isPassing(), "doesn't pass");
  }

  @SuppressWarnings("null")
  @Test
  void testMultipleAllowedValuesConflictingAllowOther() {
    MockNodeItemFactory itemFactory = new MockNodeItemFactory();

    IFlagNodeItem flag1 = itemFactory.flag(qname("value"), IStringItem.valueOf("value"));
    IFlagNodeItem flag2 = itemFactory.flag(qname("other2"), IStringItem.valueOf("other2"));

    IFlagDefinition flagDefinition = mock(IFlagDefinition.class);

    ISource source = mock(ISource.class);

    IAllowedValuesConstraint allowedValues1 = IAllowedValuesConstraint.builder()
        .source(source)
        .allowedValue(IAllowedValue.of(
            "other",
            MarkupLine.fromMarkdown("some documentation"),
            null))
        .allowsOther(true)
        .build();
    IAllowedValuesConstraint allowedValues2 = IAllowedValuesConstraint.builder()
        .source(source)
        .allowedValue(IAllowedValue.of(
            "other2",
            MarkupLine.fromMarkdown("some documentation"),
            "1.0.0"))
        .allowsOther(false)
        .build();

    List<? extends IAllowedValuesConstraint> allowedValuesConstraints
        = List.of(allowedValues1, allowedValues2);

    DynamicContext dynamicContext = new DynamicContext();

    doReturn(flagDefinition).when(flag1).getDefinition();
    doAnswer(invocation -> invocation.getArgument(0, DefaultConstraintValidator.Visitor.class)
        .visitFlag((IFlagNodeItem) invocation.getMock(), dynamicContext))
            .when(flag1).accept(any(IItemVisitor.class));
    doReturn("flag1/path").when(flag1).toPath(any(IPathFormatter.class));

    doReturn(flagDefinition).when(flag2).getDefinition();
    doAnswer(invocation -> invocation.getArgument(0, DefaultConstraintValidator.Visitor.class)
        .visitFlag((IFlagNodeItem) invocation.getMock(), dynamicContext))
            .when(flag2).accept(any(IItemVisitor.class));
    doReturn("flag1/path").when(flag2).toPath(any(IPathFormatter.class));

    doReturn(CollectionUtil.emptyMap()).when(flagDefinition).getLetExpressions();
    doReturn(allowedValuesConstraints).when(flagDefinition).getAllowedValuesConstraints();
    doReturn(CollectionUtil.emptyList()).when(flagDefinition).getExpectConstraints();
    doReturn(CollectionUtil.emptyList()).when(flagDefinition).getMatchesConstraints();
    doReturn(CollectionUtil.emptyList()).when(flagDefinition).getIndexHasKeyConstraints();

    doReturn(StaticContext.instance()).when(source).getStaticContext();

    FindingCollectingConstraintValidationHandler handler = new FindingCollectingConstraintValidationHandler();
    DefaultConstraintValidator validator = new DefaultConstraintValidator(handler);
    validator.validate(flag1, dynamicContext);
    validator.validate(flag2, dynamicContext);
    validator.finalizeValidation(dynamicContext);
    assertAll(
        () -> assertFalse(handler.isPassing(), "must pass"),
        () -> assertThat("only 1 finding", handler.getFindings(), hasSize(1)),
        () -> assertThat("finding is for a flag node", handler.getFindings(), hasItem(hasProperty("node", is(flag1)))));
  }
}
